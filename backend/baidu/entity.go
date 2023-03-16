// Package baidu provides an interface to BaiduYun object storage.
package baidu

import (
	"time"
)

// Constants for API endpoints
const (
	OpenAPIURL = "https://openapi.baidu.com"
	RootURL    = "https://pan.baidu.com"
	UploadURL  = "https://d.pcs.baidu.com"
	RootID     = "/"
)

// API URI paths
const (
	URIOauthCode   = "/oauth/2.0/device/code"
	URIOauthToken  = "/oauth/2.0/token"
	URIFile        = "/rest/2.0/xpan/file"
	URIPcsFile     = "/rest/2.0/pcs/file"
	URISuperFile   = "/rest/2.0/pcs/superfile2"
	URIMultimedia  = "/rest/2.0/xpan/multimedia"
	URIQuota       = "/api/quota"
	URIFileMeta    = "/rest/2.0/xpan/multimedia"
	URIFileManager = "/rest/2.0/xpan/file"
	URIUpload      = "/api/upload"
)

// UploadDomainOut represents the response from upload domain API
type UploadDomainOut struct {
	ErrorOut
	Host string `json:"host"` // Upload domain host
}

// Upload constants
const (
	DefaultChunkSize = 4 * 1024 * 1024 // 4MB chunk size for uploads
	DefaultListLimit = 1000            // Maximum items per list request
	TokenRefreshBuf  = 600             // Refresh token 600 seconds before expiry
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

// ============================================================================
// Authentication Response Types
// ============================================================================

// AuthCodeOut represents the response from device code authorization
type AuthCodeOut struct {
	DeviceCode      string `json:"device_code"`      // Device code for obtaining access token
	UserCode        string `json:"user_code"`        // User code to display for authorization
	VerificationURL string `json:"verification_url"` // URL for user to enter user code
	QrcodeURL       string `json:"qrcode_url"`       // QR code URL for scanning
	ExpiresIn       int    `json:"expires_in"`       // Device code expiry time in seconds
	Interval        int    `json:"interval"`         // Polling interval in seconds
}

// AccessTokenOut represents the response from token endpoint
type AccessTokenOut struct {
	ExpiresIn     int    `json:"expires_in"`     // Token validity period in seconds
	RefreshToken  string `json:"refresh_token"`  // Refresh token for obtaining new access tokens
	AccessToken   string `json:"access_token"`   // Access token for API calls
	SessionSecret string `json:"session_secret"` // Session secret
	SessionKey    string `json:"session_key"`    // Session key
	Scope         string `json:"scope"`          // Granted scopes
}

// ============================================================================
// File Entity Types
// ============================================================================

// FileEntity represents a file or directory on BaiduYun
type FileEntity struct {
	FsID           uint64 `json:"fs_id"`           // Unique file identifier
	Path           string `json:"path"`            // Absolute file path
	ServerFilename string `json:"server_filename"` // File name
	Size           uint64 `json:"size"`            // File size in bytes
	ServerMtime    uint64 `json:"server_mtime"`    // Server modification time (Unix timestamp)
	ServerCtime    uint64 `json:"server_ctime"`    // Server creation time (Unix timestamp)
	LocalMtime     uint64 `json:"local_mtime"`     // Local modification time (Unix timestamp)
	LocalCtime     uint64 `json:"local_ctime"`     // Local creation time (Unix timestamp)
	IsDir          uint   `json:"isdir"`           // Is directory: 0=file, 1=directory
	Md5            string `json:"md5"`             // File MD5 hash (only for files)
	DirEmpty       int    `json:"dir_empty"`       // Is directory empty: 0=no, 1=yes (only when web=1)
}

// ModTime returns the modification time as time.Time
func (f *FileEntity) ModTime() time.Time {
	return time.Unix(int64(f.ServerMtime), 0)
}

// IsDirectory returns true if this is a directory
func (f *FileEntity) IsDirectory() bool {
	return f.IsDir == 1
}

// FileListOut represents the response from file list API
type FileListOut struct {
	ErrorOut
	List []FileEntity `json:"list"`
}

// ============================================================================
// Error Response Types
// ============================================================================

// ErrorOut represents a standard error response
type ErrorOut struct {
	Errno  int    `json:"errno"`  // Error code
	ErrMsg string `json:"errmsg"` // Error message
}

// HasError returns true if this is an error response
func (e *ErrorOut) HasError() bool {
	return e.Errno != 0
}

// Error implements the error interface
func (e *ErrorOut) Error() string {
	if e.ErrMsg != "" {
		return e.ErrMsg
	}
	return "unknown error"
}

// ============================================================================
// Directory Operations
// ============================================================================

// MkdirOut represents the response from mkdir API
type MkdirOut struct {
	ErrorOut
	Ctime    uint64 `json:"ctime"`
	Mtime    uint64 `json:"mtime"`
	FsID     uint64 `json:"fs_id"`
	IsDir    uint   `json:"is_dir"`
	Path     string `json:"path"`
	Status   uint   `json:"status"`
	Category uint   `json:"category"`
}

// ============================================================================
// Quota Operations
// ============================================================================

// QuotaOut represents the response from quota API
type QuotaOut struct {
	Total  int64 `json:"total"`  // Total quota in bytes
	Expire bool  `json:"expire"` // Whether quota expires within 7 days
	Used   int64 `json:"used"`   // Used quota in bytes
	Free   int64 `json:"free"`   // Free quota in bytes
}

// ============================================================================
// Upload Operations
// ============================================================================

// PreUploadOut represents the response from precreate API
type PreUploadOut struct {
	ErrorOut
	Path       string `json:"path"`        // Absolute file path
	UploadID   string `json:"uploadid"`    // Upload session ID
	ReturnType int    `json:"return_type"` // Return type indicator
	BlockList  []int  `json:"block_list"`  // List of chunk indices to upload
}

// SliceUploadOut represents the response from chunk upload API
type SliceUploadOut struct {
	ErrorOut
	Md5 string `json:"md5"` // MD5 hash of uploaded chunk
}

// ============================================================================
// Download Operations
// ============================================================================

// FileInfoListOut represents the response from file metadata API
type FileInfoListOut struct {
	ErrorOut
	List []DownloadURL `json:"list"`
}

// DownloadURL represents a download URL entry
type DownloadURL struct {
	DLink string `json:"dlink"` // Download link
}

// FileManagerOp represents file manager operation types
type FileManagerOp string

const (
	FileManagerCopy   FileManagerOp = "copy"
	FileManagerMove   FileManagerOp = "move"
	FileManagerDelete FileManagerOp = "delete"
)

// FileManagerEntry represents a file operation entry
type FileManagerEntry struct {
	Path    string `json:"path"`    // Source path
	Dest    string `json:"dest"`    // Destination directory
	NewName string `json:"newname"` // New file name
	OnDup   string `json:"ondup"`   // Duplicate handling: "newcopy"
}

// FileManagerRequest represents a file manager request
type FileManagerRequest struct {
	Async    int                `json:"async"`    // Async flag: 1
	OnDup    string             `json:"ondup"`    // Duplicate handling
	FileList []FileManagerEntry `json:"filelist"` // File operations list
}
