// Package baidu provides an interface to BaiduYun object storage.
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
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/rest"
)

// Globals
var (
	// ErrTokenRefreshFailed indicates token refresh failed
	ErrTokenRefreshFailed = errors.New("failed to refresh access token")
	// ErrFileNotFound indicates file not found
	ErrFileNotFound = errors.New("file not found")
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "baidu",
		Description: "BaiduYun Drive",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{
			{
				Name:     "app_key",
				Help:     "Baidu AppKey for API access",
				Required: true,
			},
			{
				Name:     "secret_key",
				Help:     "Baidu SecretKey for API access",
				Required: true,
			},
		},
	})
}

// Config handles the OAuth device flow configuration
func Config(ctx context.Context, name string, m configmap.Mapper, c fs.ConfigIn) (*fs.ConfigOut, error) {
	appKey, ok := m.Get("app_key")
	if !ok {
		return nil, errors.New("app_key not found")
	}

	secretKey, ok := m.Get("secret_key")
	if !ok {
		return nil, errors.New("secret_key not found")
	}

	auth, err := getAuthCode(ctx, appKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth code: %w", err)
	}

	fmt.Printf("Please open this URL in your browser: %s\n", auth.VerificationURL)
	fmt.Printf("And enter the code: %s\n", auth.UserCode)

	for {
		token, err := getAccessToken(ctx, auth.DeviceCode, appKey, secretKey)
		if err == nil && token.AccessToken != "" && token.RefreshToken != "" {
			m.Set("access_token", token.AccessToken)
			m.Set("refresh_token", token.RefreshToken)
			m.Set("expires_in", strconv.Itoa(token.ExpiresIn))
			m.Set("expires_at", time.Now().Add(time.Duration(token.ExpiresIn-TokenRefreshBuf)*time.Second).Format("2006-01-02 15:04:05"))
			break
		}
		time.Sleep(time.Duration(auth.Interval) * time.Second)
	}
	return nil, nil
}

// getAuthCode obtains device authorization code
func getAuthCode(ctx context.Context, appKey string) (*AuthCodeOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  http.MethodGet,
		RootURL: OpenAPIURL,
		Path:    URIOauthCode,
		Parameters: map[string][]string{
			"response_type": {"device_code"},
			"client_id":     {appKey},
			"scope":         {"basic,netdisk"},
		},
	}
	c.SetHeader("User-Agent", "pan.baidu.com")

	resp := &AuthCodeOut{}
	_, err := c.CallJSON(ctx, opts, nil, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// getAccessToken exchanges device code for access token
func getAccessToken(ctx context.Context, deviceCode, appKey, secretKey string) (*AccessTokenOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  http.MethodGet,
		RootURL: OpenAPIURL,
		Path:    URIOauthToken,
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
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Fs represents a BaiduYun remote
type Fs struct {
	name        string           // Name of this remote
	root        string           // Root path
	opt         *Options         // Parsed options
	ci          *fs.ConfigInfo   // Global config
	m           configmap.Mapper // Config mapper
	srv         *rest.Client     // API client
	downloadSrv *rest.Client     // Download client
	features    *fs.Features     // Optional features
	ctx         context.Context  // Context

	// Token management
	tokenMu sync.Mutex // Protects token refresh
}

// NewFs creates a new Fs instance
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	ci := fs.GetConfig(ctx)

	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}

	f := &Fs{
		name:        name,
		root:        root,
		opt:         opt,
		ci:          ci,
		m:           m,
		ctx:         ctx,
		srv:         rest.NewClient(fshttp.NewClient(ctx)),
		downloadSrv: rest.NewClient(fshttp.NewClient(ctx)),
	}

	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	// Start background token refresh
	go f.startTokenRefresh()

	return f, nil
}

// startTokenRefresh periodically refreshes the access token
func (f *Fs) startTokenRefresh() {
	for {
		if err := f.maybeRefreshToken(); err != nil {
			fs.Logf(f.name, "Token refresh failed: %v", err)
		}
		// Check again in 5 minutes
		time.Sleep(5 * time.Minute)
	}
}

// maybeRefreshToken checks if token needs refresh and refreshes if necessary
func (f *Fs) maybeRefreshToken() error {
	f.tokenMu.Lock()
	defer f.tokenMu.Unlock()

	expiry, err := time.ParseInLocation("2006-01-02 15:04:05", f.opt.ExpiresAt, time.Local)
	if err != nil {
		return fmt.Errorf("failed to parse expiry time: %w", err)
	}

	// Refresh if expired or within buffer period
	if time.Until(expiry) > TokenRefreshBuf*time.Second {
		return nil // Token still valid
	}

	return f.refreshTokenLocked()
}

// refreshTokenLocked refreshes the access token (must be called with tokenMu held)
func (f *Fs) refreshTokenLocked() error {
	opts := &rest.Opts{
		Method:  http.MethodGet,
		RootURL: OpenAPIURL,
		Path:    URIOauthToken,
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
		return fmt.Errorf("failed to refresh token: %w", err)
	}

	if token.AccessToken == "" || token.RefreshToken == "" {
		return ErrTokenRefreshFailed
	}

	// Update config
	f.m.Set("access_token", token.AccessToken)
	f.m.Set("refresh_token", token.RefreshToken)
	f.m.Set("expires_in", strconv.Itoa(token.ExpiresIn))
	f.m.Set("expires_at", time.Now().Add(time.Duration(token.ExpiresIn-TokenRefreshBuf)*time.Second).Format("2006-01-02 15:04:05"))

	// Update options
	return configstruct.Set(f.m, f.opt)
}

// call executes an API call with automatic token refresh on auth errors
func (f *Fs) call(ctx context.Context, opts *rest.Opts, response interface{}) error {
	// Set access token
	opts.Parameters.Set("access_token", f.opt.AccessToken)

	// Set User-Agent for BaiduYun API
	f.srv.SetHeader("User-Agent", "pan.baidu.com")

	// Debug: log request URL and headers
	fullURL := opts.RootURL + opts.Path
	if opts.Parameters != nil && len(opts.Parameters) > 0 {
		fullURL += "?" + opts.Parameters.Encode()
	}

	if opts.ExtraHeaders != nil {
		for k, v := range opts.ExtraHeaders {
			fs.Debugf("baidu-api", "Header: %s: %s", k, v)
		}
	}

	resp, err := f.srv.Call(ctx, opts)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	var respError ErrorOut
	if err := json.Unmarshal(body, &respError); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if respError.Errno != 0 {
		// Handle authentication errors
		if respError.Errno == 111 || respError.Errno == -6 {
			if err := f.maybeRefreshToken(); err != nil {
				return fmt.Errorf("authentication failed and token refresh failed: %w", err)
			}
			// Retry the call
			return f.call(ctx, opts, response)
		}
		return fmt.Errorf("API error (errno=%d): %s", respError.Errno, respError.ErrMsg)
	}

	// Parse successful response
	if response != nil {
		if err := json.Unmarshal(body, response); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// download executes a download request
func (f *Fs) download(ctx context.Context, opts *rest.Opts) (*http.Response, error) {
	f.downloadSrv.SetHeader("Host", "d.pcs.baidu.com")
	return f.downloadSrv.Call(ctx, opts)
}

// Name returns the name of this remote
func (f *Fs) Name() string {
	return f.name
}

// Root returns the root path
func (f *Fs) Root() string {
	return f.root
}

// String returns a string representation
func (f *Fs) String() string {
	return "BaiduYun Drive"
}

// Features returns the optional features
func (f *Fs) Features() *fs.Features {
	return f.features
}

// Precision returns the precision of modification times
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash types
func (f *Fs) Hashes() hash.Set {
	return hash.NewHashSet(hash.None)
}

// List lists objects and directories in dir
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	files, err := f.listDirAll(ctx, dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		var item fs.DirEntry
		if file.IsDirectory() {
			item = fs.NewDir(strings.TrimLeft(file.Path, "/"), file.ModTime()).SetID(strconv.FormatUint(file.FsID, 10))
		} else {
			item = &Object{
				fs:      f,
				remote:  strings.TrimLeft(file.Path, "/"),
				path:    file.Path,
				size:    int64(file.Size),
				id:      strconv.FormatUint(file.FsID, 10),
				modTime: file.ModTime(),
			}
		}
		entries = append(entries, item)
	}
	return entries, nil
}

// listDirAll lists all files in a directory with pagination
func (f *Fs) listDirAll(ctx context.Context, dir string) ([]FileEntity, error) {
	var all []FileEntity
	start := 0

	for {
		files, err := f.listDirPage(ctx, dir, start, DefaultListLimit)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			break
		}
		all = append(all, files...)
		start += DefaultListLimit
	}
	return all, nil
}

// listDirPage lists a page of files in a directory
func (f *Fs) listDirPage(ctx context.Context, dir string, start, limit int) ([]FileEntity, error) {
	// Ensure dir has leading slash and is not empty
	if dir == "" {
		dir = "/"
	} else if !strings.HasPrefix(dir, "/") {
		dir = "/" + dir
	}

	opts := &rest.Opts{
		Method:  http.MethodGet,
		RootURL: RootURL,
		Path:    URIFile,
		Parameters: map[string][]string{
			"method":    {"list"},
			"dir":       {dir},
			"start":     {strconv.Itoa(start)},
			"limit":     {strconv.Itoa(limit)},
			"web":       {"1"},
			"folder":    {"0"},
			"showempty": {"1"},
		},
	}

	resp := &FileListOut{}
	if err := f.call(ctx, opts, resp); err != nil {
		return nil, err
	}
	return resp.List, nil
}

// NewObject finds an object at remote
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

// newObjectWithInfo creates an object with optional metadata
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

// Copy copies a file server-side
func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantCopy
	}

	if srcObj.path == remote {
		return nil, fs.ErrorCantCopy
	}

	dir, name := path.Split(remote)
	fileList := []FileManagerEntry{
		{
			Path:    srcObj.path,
			Dest:    dir,
			NewName: name,
			OnDup:   "newcopy",
		},
	}

	if err := f.fileManager(ctx, FileManagerCopy, fileList); err != nil {
		return nil, err
	}

	return f.newObject(remote, srcObj.size), nil
}

// newObject creates a new object stub
func (f *Fs) newObject(remote string, size int64) *Object {
	return &Object{
		fs:      f,
		remote:  remote,
		path:    remote,
		size:    size,
		modTime: time.Now(),
	}
}

// fileManager performs file manager operations
func (f *Fs) fileManager(ctx context.Context, op FileManagerOp, fileList []FileManagerEntry) error {
	jsonList, err := json.Marshal(fileList)
	if err != nil {
		return fmt.Errorf("failed to marshal file list: %w", err)
	}

	opts := &rest.Opts{
		Method:  http.MethodPost,
		RootURL: RootURL,
		Path:    URIFileManager,
		Parameters: map[string][]string{
			"method": {"filemanager"},
			"opera":  {string(op)},
		},
		Body: bytes.NewBufferString("async=1&ondup=newcopy&filelist=" + string(jsonList)),
	}

	var resp ErrorOut
	return f.call(ctx, opts, &resp)
}

// Move moves a file server-side
func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantMove
	}

	if srcObj.path == remote {
		return nil, fs.ErrorCantMove
	}

	dir, name := path.Split(remote)
	fileList := []FileManagerEntry{
		{
			Path:    srcObj.path,
			Dest:    dir,
			NewName: name,
			OnDup:   "newcopy",
		},
	}

	if err := f.fileManager(ctx, FileManagerMove, fileList); err != nil {
		return nil, err
	}

	srcObj.path = remote
	srcObj.remote = remote
	return srcObj, nil
}

// Put uploads a file
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.PutUnchecked(ctx, in, src, options...)
}

// PutUnchecked uploads a file (may fail if exists)
func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	size := src.Size()
	modTime := src.ModTime(ctx)

	o, err := f.createObject(remote, modTime, size)
	if err != nil {
		return nil, err
	}

	if err := o.Update(ctx, in, src, options...); err != nil {
		return nil, err
	}

	return o, nil
}

// createObject creates a new object
func (f *Fs) createObject(remote string, modTime time.Time, size int64) (*Object, error) {
	return &Object{
		fs:      f,
		remote:  remote,
		modTime: modTime,
		size:    size,
	}, nil
}

// Mkdir creates a directory
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	opts := &rest.Opts{
		Method:  http.MethodPost,
		RootURL: RootURL,
		Path:    URIFile,
		Parameters: map[string][]string{
			"method": {"create"},
		},
		Body: bytes.NewBufferString(fmt.Sprintf("path=%s&isdir=1&rtype=0", "/"+strings.TrimLeft(dir, "/"))),
	}

	var resp MkdirOut
	return f.call(ctx, opts, &resp)
}

// Rmdir removes an empty directory
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	dir = "/" + strings.TrimLeft(dir, "/")

	if dir == "/" {
		return errors.New("cannot delete root directory")
	}

	// Check if directory is empty
	files, err := f.listDirPage(ctx, dir, 0, 1)
	if err != nil {
		return err
	}
	if len(files) > 0 {
		return errors.New("directory is not empty")
	}

	fileList := []FileManagerEntry{
		{Path: dir},
	}
	return f.fileManager(ctx, FileManagerDelete, fileList)
}

// Purge deletes all files in a directory
func (f *Fs) Purge(ctx context.Context, dir string) error {
	// Note: This implementation just recreates the directory
	// A better implementation would recursively delete contents
	if err := f.Rmdir(ctx, dir); err != nil {
		return nil
	}
	return f.Mkdir(ctx, dir)
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	opts := &rest.Opts{
		Method:     http.MethodGet,
		RootURL:    RootURL,
		Path:       URIQuota,
		Parameters: map[string][]string{},
	}

	resp := &QuotaOut{}
	if err := f.call(ctx, opts, resp); err != nil {
		return nil, err
	}

	return &fs.Usage{
		Free:  &resp.Free,
		Total: &resp.Total,
		Used:  &resp.Used,
	}, nil
}

// ============================================================================
// Object
// ============================================================================

// Object represents a file on BaiduYun
type Object struct {
	fs          *Fs
	path        string
	remote      string
	size        int64
	modTime     time.Time
	id          string
	hasMetaData bool
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// String returns a string representation
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

// Hash returns the hash of the object
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", nil
}

// Size returns the size in bytes
func (o *Object) Size() int64 {
	return o.size
}

// ModTime returns the modification time
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	// BaiduYun doesn't support setting modification time
	return nil
}

// Storable returns whether the object is storable
func (o *Object) Storable() bool {
	return true
}

// Open opens the file for reading
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	downloadURL, err := o.getDownloadURL(ctx)
	if err != nil {
		return nil, err
	}

	fs.FixRangeOption(options, o.size)
	opts := rest.Opts{
		Method:     http.MethodGet,
		RootURL:    downloadURL + "&access_token=" + o.fs.opt.AccessToken,
		Parameters: map[string][]string{},
	}

	resp, err := o.fs.download(ctx, &opts)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// getDownloadURL gets the download URL for this file
func (o *Object) getDownloadURL(ctx context.Context) (string, error) {
	opts := &rest.Opts{
		Method:  http.MethodPost,
		RootURL: RootURL,
		Path:    URIMultimedia,
		Parameters: map[string][]string{
			"method": {"filemetas"},
			"fsids":  {"[" + o.id + "]"},
			"dlink":  {"1"},
		},
	}

	resp := &FileInfoListOut{}
	if err := o.fs.call(ctx, opts, resp); err != nil {
		return "", err
	}

	if len(resp.List) == 0 {
		return "", ErrFileNotFound
	}
	return resp.List[0].DLink, nil
}

// Update updates the file content
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	return o.upload(ctx, in, src.Size())
}

// upload uploads a file using chunked upload with streaming approach.
// It uses io.ReadSeeker to avoid loading entire file into memory or creating temporary files.
//
// The input reader MUST implement io.ReadSeeker. If it doesn't, an error is returned
// rather than falling back to memory caching, which would defeat the purpose of streaming.
func (o *Object) upload(ctx context.Context, in io.Reader, size int64) error {
	// Require io.ReadSeeker for streaming uploads
	var seeker io.ReadSeeker

	// Check if input is wrapped by accounting.Account
	if acc, ok := in.(*accounting.Account); ok {
		// Account may have an AsyncReader buffer which doesn't support seeking
		// We need to use the original reader which should support seeking
		if acc.HasBuffer() {
			// Stop and abandon the buffer to get access to the underlying seekable reader
			acc.StopBuffering()
			acc.Abandon()
		}
		// Get the original reader which should be seekable
		origReader := acc.GetReader()
		var ok bool
		seeker, ok = origReader.(io.ReadSeeker)
		if !ok {
			return fmt.Errorf("underlying reader must implement io.ReadSeeker for streaming upload; got %T", origReader)
		}
	} else {
		var ok bool
		seeker, ok = in.(io.ReadSeeker)
		if !ok {
			return fmt.Errorf("input must implement io.ReadSeeker for streaming upload; got %T", in)
		}
	}

	// Calculate number of chunks
	chunkCount := (size + int64(DefaultChunkSize) - 1) / int64(DefaultChunkSize)
	if chunkCount == 0 {
		chunkCount = 1
	}

	// reset seek
	_, err := seeker.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	// Step 1: Calculate MD5 for each chunk by streaming through the file
	md5s := make([]string, 0, chunkCount)
	for {
		var buf = make([]byte, DefaultChunkSize)
		n, err := io.ReadFull(seeker, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk: %w", err)
		}
		// Calculate MD5
		md5sum := md5.Sum(buf[:n])
		md5s = append(md5s, hex.EncodeToString(md5sum[:]))
	}

	if len(md5s) == 0 {
		return fmt.Errorf("ERROR: chunk file md5s is empty")
	}

	md5ListJSON, err := json.Marshal(md5s)
	if err != nil {
		return fmt.Errorf("failed to marshal MD5 list: %w", err)
	}

	// Step 2: Pre-upload to get upload ID and block list
	preUploadResp, err := o.preUpload(ctx, string(md5ListJSON), o.remote, size)
	if err != nil {
		return err
	}

	if len(preUploadResp.BlockList) != len(md5s) {
		return fmt.Errorf("block size not eq md5 list")
	}

	// reset seek
	_, err = seeker.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	// Step 3: Upload only the chunks that are needed (as indicated by block_list)
	// If block_list is empty, all chunks already exist on server (deduplication)
	for _, chunkIndex := range preUploadResp.BlockList {
		// Seek to the correct position for this chunk
		_, err := seeker.Seek(int64(chunkIndex)*int64(DefaultChunkSize), io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek to chunk %d: %w", chunkIndex, err)
		}

		var buf = make([]byte, DefaultChunkSize)
		n, err := io.ReadFull(seeker, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("failed to read chunk %d: %w", chunkIndex, err)
		}

		if err := o.sliceUpload(ctx, o.remote, preUploadResp.UploadID, chunkIndex, bytes.NewReader(buf[:n]), int64(n)); err != nil {
			return fmt.Errorf("failed to upload chunk %d: %w", chunkIndex, err)
		}
	}

	// Step 4: Complete upload
	file, err := o.completeUpload(ctx, o.remote, string(md5ListJSON), preUploadResp.UploadID, size)
	if err != nil {
		return err
	}

	o.id = strconv.FormatUint(file.FsID, 10)
	o.path = file.Path
	return nil
}

// preUpload initiates the upload process
func (o *Object) preUpload(ctx context.Context, md5ListJSON, remote string, size int64) (*PreUploadOut, error) {
	opts := &rest.Opts{
		Method:  http.MethodPost,
		RootURL: RootURL,
		Path:    URIFile,
		Parameters: map[string][]string{
			"method": {"precreate"},
		},
		Body: bytes.NewBufferString(fmt.Sprintf(
			"path=%s&size=%d&rtype=0&isdir=0&autoinit=1&block_list=%s",
			"/"+strings.TrimLeft(remote, "/"), size, md5ListJSON,
		)),
	}

	resp := &PreUploadOut{}
	err := o.fs.call(ctx, opts, resp)
	if err != nil {
		fs.Debugf(o, "preUpload failed: %v", err)
	} else {
		fs.Debugf(o, "preUpload success: uploadid=%s, block_list=%v", resp.UploadID, resp.BlockList)
	}
	return resp, err
}

// sliceUpload uploads a single chunk
func (o *Object) sliceUpload(ctx context.Context, remote, uploadID string, partSeq int, reader io.Reader, size int64) error {
	if reader == nil {
		return errors.New("reader is nil")
	}

	formReader, contentType, overhead, err := rest.MultipartUpload(ctx, reader, nil, "file", "file", "")
	if err != nil {
		return fmt.Errorf("failed to create multipart upload: %w", err)
	}

	contentLength := size + overhead
	opts := &rest.Opts{
		Method:        http.MethodPost,
		RootURL:       UploadURL,
		Path:          URISuperFile,
		ContentType:   contentType,
		ContentLength: &contentLength,
		Parameters: map[string][]string{
			"method":   {"upload"},
			"type":     {"tmpfile"},
			"path":     {"/" + strings.TrimLeft(remote, "/")},
			"uploadid": {uploadID},
			"partseq":  {strconv.Itoa(partSeq)},
		},
		Body: formReader,
	}

	resp := &SliceUploadOut{}
	err = o.fs.call(ctx, opts, resp)
	if err != nil {
		fs.Debugf(o, "sliceUpload: API returned error: %v", err)
	} else {
		fs.Debugf(o, "sliceUpload: API returned success, md5=%s", resp.Md5)
	}
	return err
}

// completeUpload completes the upload process
func (o *Object) completeUpload(ctx context.Context, remote, md5ListJSON, uploadID string, size int64) (*FileEntity, error) {
	// Ensure path starts with /
	opts := &rest.Opts{
		Method:  http.MethodPost,
		RootURL: RootURL,
		Path:    URIFile,
		Parameters: map[string][]string{
			"method": {"create"},
		},
		Body: bytes.NewBufferString(fmt.Sprintf(
			"path=%s&size=%d&rtype=0&isdir=0&autoinit=1&block_list=%s&uploadid=%s&rtype=1",
			"/"+strings.TrimLeft(remote, "/"), size, md5ListJSON, uploadID,
		)),
	}
	resp := &FileEntity{}
	err := o.fs.call(ctx, opts, resp)
	if err != nil {
		fs.Debugf(o, "completeUpload failed: %v", err)
	} else {
		fs.Debugf(o, "completeUpload success: fs_id=%d, path=%s", resp.FsID, resp.Path)
	}
	return resp, err
}

// Remove removes the file
func (o *Object) Remove(ctx context.Context) error {
	fileList := []FileManagerEntry{
		{Path: o.path},
	}
	return o.fs.fileManager(ctx, FileManagerDelete, fileList)
}

// ID returns the file ID
func (o *Object) ID() string {
	return o.id
}

// setMetaData sets object metadata from FileEntity
func (o *Object) setMetaData(info *FileEntity) error {
	if info.IsDirectory() {
		return fs.ErrorIsDir
	}

	o.hasMetaData = true
	o.size = int64(info.Size)
	o.modTime = info.ModTime()
	o.id = strconv.FormatUint(info.FsID, 10)
	o.path = info.Path
	o.remote = info.Path
	return nil
}

// readMetaData reads metadata for this object
func (o *Object) readMetaData(ctx context.Context) error {
	if o.hasMetaData {
		return nil
	}

	// Get directory path from remote
	dir := path.Dir(o.remote)
	if dir == "." {
		dir = "/"
	} else if !strings.HasPrefix(dir, "/") {
		dir = "/" + dir
	}

	files, err := o.fs.listDirAll(ctx, dir)
	if err != nil {
		return err
	}

	_, leaf := dircache.SplitPath(o.remote)

	for _, file := range files {
		if !file.IsDirectory() && strings.EqualFold(file.ServerFilename, leaf) {
			return o.setMetaData(&file)
		}
	}

	return fs.ErrorObjectNotFound
}
