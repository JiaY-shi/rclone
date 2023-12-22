package baidu

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rclone/rclone/lib/dircache"

	"github.com/rclone/rclone/fs/config/configstruct"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/rest"
)

const (
	openApiUrl = "https://openapi.baidu.com"
	rootUrl    = "https://pan.baidu.com"
	uploadUrl  = "https://d.pcs.baidu.com"
	rootId     = "/"

	//uri
	uriOauthCode  = "/oauth/2.0/device/code"
	uriOauthToken = "/oauth/2.0/token"
	uriFile       = "/rest/2.0/xpan/file"
	uriSuperFile  = "/rest/2.0/pcs/superfile2"
	uriMultimedia = "/rest/2.0/xpan/multimedia"
	uriQuota      = "/api/quota"

	//
	chunkSize = 4 * 1024 * 1024 //分片大小4M
)

// Options defines the configuration for this backend
type Options struct {
	AppKey       string `config:"app_key"`
	SecretKey    string `config:"secret_key"`
	AccessToken  string `config:"access_token"`
	RefreshToken string `config:"refresh_token"`
	ExpiresIn    int    `config:"expires_in"`
	ExpiresAt    string `config:"expires_at"`
}

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "baidu",
		Description: "BaiduYun Drive",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{{
			Name:     "app_key",
			Help:     "Please enter AppKey",
			Required: true,
		}, {
			Name:     "secret_key",
			Help:     "Please enter SecretKey",
			Required: true,
		}},
	})
}

// Config callback
func Config(ctx context.Context, name string, m configmap.Mapper, c fs.ConfigIn) (*fs.ConfigOut, error) {
	appKey, ok := m.Get("app_key")
	if !ok {
		return nil, errors.New("AppKey not found")
	}

	secretKey, ok := m.Get("secret_key")
	if !ok {
		return nil, errors.New("SecretKey not found")
	}

	auth, err := authCode(ctx, appKey)
	if err != nil {
		return nil, err
	}

	fmt.Printf("请在浏览器中打开链接：%s ,并在打开的页面中输入：%s 获取授权。\n", auth.VerificationUrl, auth.UserCode)

	for {
		token, err := getAccessToken(ctx, auth.DeviceCode, appKey, secretKey)
		if err == nil && token.AccessToken != "" && token.RefreshToken != "" {
			m.Set("access_token", token.AccessToken)
			m.Set("refresh_token", token.RefreshToken)
			m.Set("expires_in", strconv.Itoa(token.ExpiresIn))
			m.Set("expires_at", time.Now().Add(time.Duration(token.ExpiresIn-600)*time.Second).Format("2006-01-02 15:04:05"))
			break
		}
		time.Sleep(time.Second * time.Duration(auth.Interval))
	}
	return nil, nil
}

func getAccessToken(ctx context.Context, deviceCode, appKey, secretKey string) (*AccessTokenOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  "GET",
		RootURL: openApiUrl,
		Path:    uriOauthToken,
		Parameters: map[string][]string{
			"grant_type":    {"device_token"},
			"code":          {deviceCode},
			"client_id":     {appKey},
			"client_secret": {secretKey},
		},
	}
	c.SetHeader("User-Agent", "pan.baidu.com")
	resp := &AccessTokenOut{}
	_, err := c.CallJSON(ctx, opts, nil, resp)
	return resp, err
}

// 授权
func authCode(ctx context.Context, appKey string) (*AuthCodeOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  "GET",
		RootURL: openApiUrl,
		Path:    uriOauthCode,
		Parameters: map[string][]string{
			"response_type": {"device_code"},
			"client_id":     {appKey},
			"scope":         {"basic,netdisk"},
		},
	}
	c.SetHeader("User-Agent", "pan.baidu.com")
	resp := &AuthCodeOut{}
	_, err := c.CallJSON(ctx, opts, nil, resp)
	return resp, err
}

// NewFs constructs an Fs from the path, bucket:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	ci := fs.GetConfig(ctx)

	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	f := &Fs{
		name:        name,
		ci:          ci,
		srv:         rest.NewClient(fshttp.NewClient(ctx)),
		downloadSrv: rest.NewClient(fshttp.NewClient(ctx)),
		root:        root,
		ctx:         ctx,
		opt:         opt,
		m:           m,
	}

	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)
	go f.reWriteConfig()
	return f, err
}

func (f *Fs) reWriteConfig() {
	for {
		t, err := time.ParseInLocation("2006-01-02 15:04:05", f.opt.ExpiresAt, time.Local)
		if err != nil {
			t = time.Now()
		}
		sub := t.Sub(time.Now())
		if sub < 0 {
			sub = 5 * time.Minute
		}
		trigger := time.After(sub)
		<-trigger
		f.refreshToken()
	}
}

type Fs struct {
	name        string
	ci          *fs.ConfigInfo
	srv         *rest.Client
	downloadSrv *rest.Client
	features    *fs.Features
	root        string
	ctx         context.Context
	opt         *Options
	m           configmap.Mapper
}

func (f *Fs) call(ctx context.Context, opts *rest.Opts, response interface{}) error {
	//设置AccessToken
	opts.Parameters.Set("access_token", f.opt.AccessToken)
	resp, err := f.srv.Call(ctx, opts)
	if err != nil {
		return err
	}

	respError := ErrorOut{}
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &respError)
	if respError.Errno != 0 {
		if respError.Errno == 111 || respError.Errno == -6 {
			err = f.refreshToken()
			if err != nil {
				return err
			}
			return f.call(ctx, opts, response)
		}
		return fmt.Errorf("errno: %d,errmsg: %s", respError.Errno, respError.ErrMsg)
	}
	json.Unmarshal(b, response)
	return nil
}

func (f *Fs) download(ctx context.Context, opts *rest.Opts) (resp *http.Response, err error) {
	//设置AccessToken
	//opts.Parameters.Set("access_token", f.opt.AccessToken)
	f.downloadSrv.SetHeader("Host", "d.pcs.baidu.com")
	return f.downloadSrv.Call(ctx, opts)
}

func (f *Fs) refreshToken() error {
	opts := &rest.Opts{
		Method:  "GET",
		RootURL: openApiUrl,
		Path:    uriOauthToken,
		Parameters: map[string][]string{
			"grant_type":    {"refresh_token"},
			"refresh_token": {f.opt.RefreshToken},
			"client_id":     {f.opt.AppKey},
			"client_secret": {f.opt.SecretKey},
		},
	}
	f.srv.SetHeader("User-Agent", "pan.baidu.com")
	token := &AccessTokenOut{}
	_, err := f.srv.CallJSON(f.ctx, opts, nil, token)
	if err != nil {
		return err
	}

	if token.AccessToken != "" && token.RefreshToken != "" {
		f.m.Set("access_token", token.AccessToken)
		f.m.Set("refresh_token", token.RefreshToken)
		f.m.Set("expires_in", strconv.Itoa(token.ExpiresIn))
		f.m.Set("expires_at", time.Now().Add(time.Duration(token.ExpiresIn-600)*time.Second).Format("2006-01-02 15:04:05"))
	}
	return configstruct.Set(f.m, f.opt)
}

// Name 返回名称
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return "BaiduYun Drive"
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision of the ModTimes in this Fs
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Returns the supported hash types of the filesystem
func (f *Fs) Hashes() hash.Set {
	return hash.NewHashSet(hash.None)
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	list, err := f.listDirAllFile(ctx, "/"+strings.TrimLeft(dir, "/"))
	if err != nil {
		return nil, err
	}

	for _, info := range list {
		var item fs.DirEntry
		if info.IsDir == 1 {
			item = fs.NewDir(strings.TrimLeft(info.Path, "/"), time.Unix(int64(info.ServerMtime), 0)).SetID(strconv.FormatUint(info.FsId, 10))
		} else {
			item = &Object{
				fs:      f,
				remote:  strings.TrimLeft(info.Path, "/"),
				path:    info.Path,
				size:    int64(info.Size),
				id:      strconv.FormatUint(info.FsId, 10),
				modTime: time.Unix(int64(info.ServerMtime), 0),
			}
		}
		entries = append(entries, item)
	}
	return
}

func (f *Fs) listDirAllFile(ctx context.Context, dir string) ([]FileEntity, error) {
	start := 0
	var all []FileEntity
	for {
		list, err := f.listDirFile(ctx, dir, start, 1000)
		if err != nil {
			return nil, err
		}
		if len(list) == 0 {
			break
		}
		start += 1000
		all = append(all, list...)
	}
	return all, nil
}

func (f *Fs) listDirFile(ctx context.Context, dir string, start, limit int) ([]FileEntity, error) {
	opts := &rest.Opts{
		Method:  "GET",
		RootURL: rootUrl,
		Path:    uriFile,
		Parameters: map[string][]string{
			"method":       {"list"},
			"access_token": {f.opt.AccessToken},
			"dir":          {dir},
			"start":        {strconv.Itoa(start)},
			"limit":        {strconv.Itoa(limit)},
			"web":          {"1"},
			"folder":       {"0"},
			"showempty":    {"1"},
		},
	}
	resp := &FileListOut{}
	err := f.call(ctx, opts, resp)
	if err != nil {
		return nil, err
	}
	return resp.List, nil
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error ErrorObjectNotFound.
//
// If remote points to a directory then it should return
// ErrorIsDir if possible without doing any extra work,
// otherwise ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *FileEntity) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	var err error
	if info != nil {
		err = o.setMetaData(info)
	} else {
		err = o.readMetaData(ctx)
	}
	return o, err
}

// Copy src to this remote using server-side copy operations.
//
// # This is stored with the remote path given
//
// # It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantCopy
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantCopy
	}

	if srcObj.path == remote {
		return nil, fs.ErrorCantCopy
	}
	p, name := path.Split(remote)
	fileList := fmt.Sprintf(`[{"path":"%s","dest":"%s","newname":"%s","ondup":"newcopy"}]`, srcObj.path, p, name)
	err := f.fileManager(ctx, "copy", fileList)
	if err != nil {
		return nil, err
	}
	return f.newObject(remote, srcObj.size), nil
}

func (f *Fs) newObject(path string, size int64) *Object {
	return &Object{fs: f, remote: path, path: path, size: size, modTime: time.Now()}
}

// 文件操作统一方法
func (f *Fs) fileManager(ctx context.Context, opera, fileList string) error {
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriFile,
		Parameters: map[string][]string{
			"method": {"filemanager"},
			"opera":  {opera},
		},
		Body: bytes.NewBuffer([]byte("async=1&ondup=newcopy&filelist=" + fileList)),
	}
	resp := &ErrorOut{}
	return f.call(ctx, opts, resp)
}

// Move src to this remote using server-side move operations.
//
// # This is stored with the remote path given
//
// # It returns the destination Object and a possible error
//
// Will only be called if src.Fs().Name() == f.Name()
//
// If it isn't possible then return fs.ErrorCantMove
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantMove
	}
	if srcObj.path == remote {
		return nil, fs.ErrorCantMove
	}
	p, name := path.Split(remote)
	fileList := fmt.Sprintf(`[{"path":"%s","dest":"%s","newname":"%s","ondup":"newcopy"}]`, srcObj.path, p, name)
	err := f.fileManager(ctx, "move", fileList)
	if err != nil {
		return nil, err
	}
	srcObj.path = remote
	srcObj.remote = remote
	return srcObj, nil
}

// Put in to the remote path with the modTime given of the given size
//
// When called from outside an Fs by rclone, src.Size() will always be >= 0.
// But for unknown-sized objects (indicated by src.Size() == -1), Put should either
// return an error or upload it properly (rather than e.g. calling panic).
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.PutUnchecked(ctx, in, src, options...)
}

// PutUnchecked the object into the container
//
// # This will produce an error if the object already exists
//
// # Copy the reader in to the new object which is returned
//
// The new object may have been created if an error is returned
func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	size := src.Size()
	modTime := src.ModTime(ctx)

	o, err := f.createObject(ctx, remote, modTime, size)
	if err != nil {
		return nil, err
	}
	return o, o.Update(ctx, in, src, options...)

}

// Creates from the parameters passed in a half finished Object which
// must have setMetaData called on it
//
// # Returns the object, leaf, directoryID and error
//
// Used to create new objects
func (f *Fs) createObject(ctx context.Context, remote string, modTime time.Time, size int64) (o *Object, err error) {
	// Temporary Object under construction
	o = &Object{
		fs:      f,
		remote:  remote,
		modTime: modTime,
		size:    size,
	}
	return o, nil
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriFile,
		Parameters: map[string][]string{
			"method": {"create"},
		},
		Body: bytes.NewBuffer([]byte(fmt.Sprintf("path=%s&isdir=1&rtype=0", "/"+strings.TrimLeft(dir, "/")))),
	}
	resp := MkdirOut{}
	return f.call(ctx, opts, resp)
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	dir = "/" + strings.TrimLeft(dir, "/")
	if dir == "/" {
		return errors.New("the root directory cannot be deleted")
	}
	list, err := f.listDirFile(ctx, dir, 0, 1)
	if err != nil {
		return err
	}
	if len(list) != 0 {
		return errors.New("directory is not be empty")
	}
	fileList := fmt.Sprintf(`[{"path":"%s"}]`, dir)
	return f.fileManager(ctx, "delete", fileList)
}

// Purge all files in the directory specified
//
// Implement this if you have a way of deleting all the files
// quicker than just running Remove() on the result of List()
//
// Return an error if it doesn't exist
func (f *Fs) Purge(ctx context.Context, dir string) error {
	err := f.Rmdir(ctx, dir)
	if err != nil {
		return nil
	}
	return f.Mkdir(ctx, dir)
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (usage *fs.Usage, err error) {
	opts := &rest.Opts{
		Method:     "GET",
		RootURL:    rootUrl,
		Path:       uriQuota,
		Parameters: map[string][]string{},
	}
	resp := QuotaOut{}
	if err = f.call(ctx, opts, resp); err != nil {
		return nil, err
	}
	usage = &fs.Usage{
		Free:  &resp.Free,
		Total: &resp.Total,
		Used:  &resp.Used,
	}
	return usage, nil
}

type Object struct {
	fs          *Fs // what this object is part of
	path        string
	remote      string    // The remote path
	size        int64     // size of the object
	modTime     time.Time // modification time of the object
	id          string    // ID of the object
	hasMetaData bool      //
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the SHA-1 of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", nil
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.size
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return nil
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	downloadUrl, err := o.fileDownloadUrl(ctx)
	if err != nil {
		return nil, err
	}
	return o.download(ctx, downloadUrl, options...)
}

func (o *Object) download(ctx context.Context, downloadUrl string, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	fs.FixRangeOption(options, o.size)
	opts := rest.Opts{
		Method:     "GET",
		RootURL:    downloadUrl + "&access_token=" + o.fs.opt.AccessToken,
		Parameters: map[string][]string{},
		//Options: options,
	}
	resp, err := o.fs.download(ctx, &opts)
	if err != nil {
		return nil, err
	}
	return resp.Body, err
}

func (o *Object) fileDownloadUrl(ctx context.Context) (string, error) {
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriMultimedia,
		Parameters: map[string][]string{
			"method": {"filemetas"},
			"fsids":  {"[" + o.id + "]"},
			"dlink":  {"1"},
		},
	}
	resp := FileInfoListOut{}
	err := o.fs.call(ctx, opts, &resp)
	if err != nil {
		return "", err
	}
	if len(resp.List) == 0 {
		return "", errors.New("")
	}
	return resp.List[0].DLink, nil
}

// Update the object with the contents of the io.Reader, modTime and size
//
// # If existing is set then it updates the object rather than creating a new one
//
// The new object may have been created if an error is returned
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (err error) {
	return o.upload(ctx, in, src.Size())
}

func fileMd5(file *os.File) string {
	file.Seek(0, 0)
	hash := md5.New()
	io.Copy(hash, file)
	return hex.EncodeToString(hash.Sum(nil))
}

func (o *Object) upload(ctx context.Context, in io.Reader, size int64) error {
	var md5s []string
	var files []*os.File

	defer func() {
		for _, f := range files {
			if f != nil {
				os.Remove(f.Name())
				f.Close()
			}
		}
	}()

	for {
		tFile, err := os.CreateTemp("", "rclone_baidu_")
		if err != nil {
			return err
		}
		n, err := io.CopyN(tFile, in, chunkSize)
		if err != nil && n == 0 {
			os.Remove(tFile.Name())
			tFile.Close()
			if err == io.EOF {
				break
			}
			return err
		}
		md5s = append(md5s, fileMd5(tFile))
		files = append(files, tFile)
	}
	md5ListBytes, _ := json.Marshal(md5s)

	out, err := o.preUpload(ctx, string(md5ListBytes), o.remote, size)
	if err != nil {
		return err
	}

	if len(out.BlockList) != len(files) {
		return errors.New("file chunk size is error")
	}

	for k, file := range files {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		err = o.sliceUpload(ctx, o.remote, out.UploadId, k, file, info.Size())
		if err != nil {
			return err
		}
		os.Remove(file.Name())
		file.Close()
	}
	file, err := o.complete(ctx, o.remote, string(md5ListBytes), out.UploadId, size)
	if err != nil {
		return err
	}
	o.id = strconv.FormatUint(file.FsId, 10)
	o.path = file.Path
	return nil
}

// 预上传
func (o *Object) preUpload(ctx context.Context, md5ListJson string, remote string, size int64) (PreUploadOut, error) {
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriFile,
		Parameters: map[string][]string{
			"method": {"precreate"},
		},
		Body: bytes.NewBuffer([]byte(fmt.Sprintf("path=%s&size=%d&rtype=0&isdir=0&autoinit=1&block_list=%s", "/"+strings.TrimLeft(remote, "/"), size, md5ListJson))),
	}
	resp := PreUploadOut{}
	err := o.fs.call(ctx, opts, &resp)
	return resp, err
}

// 分片上传
func (o *Object) sliceUpload(ctx context.Context, remote, uploadId string, partSeq int, file *os.File, size int64) (err error) {
	if file == nil {
		return errors.New("file error")
	}
	file.Seek(0, 0)
	formReader, contentType, overhead, err := rest.MultipartUpload(ctx, file, nil, "file", "file")
	if err != nil {
		return fmt.Errorf("failed to make multipart upload for 0 length file: %w", err)
	}
	contentLength := size + overhead
	opts := &rest.Opts{
		Method:        "POST",
		RootURL:       uploadUrl,
		Path:          uriSuperFile,
		ContentType:   contentType,
		ContentLength: &contentLength,
		Parameters: map[string][]string{
			"method":   {"upload"},
			"type":     {"tmpfile"},
			"path":     {"/" + strings.TrimLeft(remote, "/")},
			"uploadid": {uploadId},
			"partseq":  {strconv.Itoa(partSeq)},
		},
		Body: formReader,
	}
	resp := SliceUploadOut{}
	return o.fs.call(ctx, opts, &resp)
}

// 完成上传
func (o *Object) complete(ctx context.Context, remote, md5ListJson, uploadId string, size int64) (FileEntity, error) {
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriFile,
		Parameters: map[string][]string{
			"method": {"create"},
		},
		Body: bytes.NewBuffer([]byte(fmt.Sprintf("path=%s&size=%d&rtype=0&isdir=0&autoinit=1&block_list=%s&uploadid=%s", "/"+strings.TrimLeft(remote, "/"), size, md5ListJson, uploadId))),
	}
	resp := FileEntity{}
	err := o.fs.call(ctx, opts, &resp)
	return resp, err
}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	fileList := fmt.Sprintf(`[{"path":"%s"}]`, o.path)
	return o.fs.fileManager(ctx, "delete", fileList)
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return o.id
}

// setMetaData sets the metadata from info
func (o *Object) setMetaData(info *FileEntity) (err error) {
	if info.IsDir == 1 {
		return fs.ErrorIsDir
	}
	o.hasMetaData = true
	o.size = int64(info.Size)
	o.modTime = time.Unix(int64(info.ServerMtime), 0)
	o.id = strconv.FormatUint(info.FsId, 10)
	o.path = info.Path
	o.remote = info.Path
	return nil
}

func (o *Object) readMetaData(ctx context.Context) (err error) {
	if o.hasMetaData {
		return nil
	}

	list, err := o.fs.listDirAllFile(ctx, o.remote)
	if err != nil {
		return err
	}

	_, leaf := dircache.SplitPath(o.remote)

	var info FileEntity
	for _, v := range list {
		if v.IsDir == 0 && strings.EqualFold(v.ServerFilename, leaf) {
			info = v
			break
		}
	}
	return o.setMetaData(&info)
}
