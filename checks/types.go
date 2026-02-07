package checks

// Security check results
type Security struct {
	Firewall            string
	FirewallRules       int
	SSHStatus           string
	SSHPort             int
	SSHPasswordAuth     string // Changed to string: "yes", "no", "skipped"
	SSHRootLogin        string
	SSHProtocol         string
	SSHAllowUsers       string
	SSHConfigReadable   bool // Track if we could read the config
	Fail2banStatus      string
	Fail2banJails       int
	Fail2banJailNames   []string
	Fail2banBanned      int
	SSLCerts            int
	SSLExpires          string
	SSLExpiringSoon     int
	SSLDomains          []string
	RootUsers           int
	ShellUsers          []string
	FailedLogins        int
	OpenPorts           []int
	ExternalPorts       []int
	LocalOnlyPorts      []int
	UnusualPorts        []int
	ExternalPortDetails []PortDetail
	LocalPortDetails    []PortDetail
	SUIDCount           int
	SUIDPaths           []string
	WorldWritable       int
	RecentEtcMods       int
	ExternalConns       int
	TopIPs              []IPConnection
}

type PortDetail struct {
	Port    int
	Process string
	Bind    string
}

// Services check results
type Services struct {
	TotalRunning int
	Failed       int
	FailedNames  []string
	AutoRestart  int
	WebServer    string
	WebStatus    string
	Database     string
	DBStatus     string
	AppServer    string
	AppStatus    string
	DockerStatus string
	SSHStatus    string
	CronStatus   string
}

// Resources check results
type Resources struct {
	CPULoad1     float64     `json:"cpuload1"`
	CPULoad5     float64     `json:"cpuload5"`
	CPULoad15    float64     `json:"cpuload15"`
	CPUPercent   float64     `json:"cpu_percent"`
	MemTotal     uint64      `json:"mem_total"`
	MemUsed      uint64      `json:"mem_used"`
	MemPercent   float64     `json:"mem_percent"`
	SwapTotal    uint64      `json:"swap_total"`
	SwapUsed     uint64      `json:"swap_used"`
	SwapPercent  float64     `json:"swap_percent"`
	DiskMounts   []DiskMount `json:"disk_mounts"`
	TopProcesses []Process   `json:"top_processes"`
	LargeLogs    []LogFile   `json:"large_logs"`
}

type DiskMount struct {
	Path    string
	Total   uint64
	Used    uint64
	Percent float64
}

type Process struct {
	Name   string
	Memory uint64
}

type LogFile struct {
	Path string
	Size uint64
}

// Storage check results
type Storage struct {
	DiskHealth       string
	DisksChecked     int
	InodeUsage       []InodeInfo
	IOWait           float64
	FilesystemErrors int
}

type InodeInfo struct {
	Mount   string
	Percent float64
}

// Database check results
type Database struct {
	PostgreSQL PostgreSQLInfo
	MySQL      MySQLInfo
	Redis      RedisInfo
}

type PostgreSQLInfo struct {
	Available     bool
	Databases     int
	DatabaseNames []string
	TotalSize     string
	Connections   int
	SlowQueries   int
	ConnLimit     int
}

type MySQLInfo struct {
	Available     bool
	Databases     int
	DatabaseNames []string
	TotalSize     string
	Connections   int
}

type RedisInfo struct {
	Available bool
	Memory    string
	Clients   int
}

// Docker check results
type Docker struct {
	Available     bool
	Running       int
	Stopped       int
	Images        int
	ImagesSize    string
	Volumes       int
	VolumesSize   string
	TopContainers []Container
}

type Container struct {
	Name       string
	CPUPercent float64
	Memory     string
}

// System check results
type System struct {
	ListeningPorts  int
	ActiveConns     int
	CronJobs        int
	SystemdTimers   int
	LastReboot      string
	PendingUpdates  int
	SecurityUpdates int
	NTPSync         bool
	NTPOffset       string
}

// Logs check results
type Logs struct {
	SyslogErrors    int
	SSHFailed       int
	SSHFailedIPs    []string
	ServiceRestarts []ServiceRestart
}

type ServiceRestart struct {
	Service  string
	Count    int
	LastTime string
}

// Network check results
type Network struct {
	DNSResolution string
	DNSLatency    string
	PingLatency   string
	PacketLoss    float64
	Interfaces    []NetInterface
	TopIPs        []IPConnection
}

type NetInterface struct {
	Name   string
	IP     string
	Status string
}

type IPConnection struct {
	IP    string
	Count int
}

// Backups check results
type Backups struct {
	BackupDir   string
	DirExists   bool
	LastBackup  string
	BackupSize  string
	RecentFiles []string
	CronJobs    int
}

type SystemTuning struct {
	NTPStatus              string
	NTPService             string
	FileDescriptorsCurrent int
	FileDescriptorsMax     int
	SysctlParams           map[string]string
}

type CronJob struct {
	User    string
	Command string
	Schedule string
}

type SystemdTimer struct {
	Name     string
	NextRun  string
	LastRun  string
}

type ConnectionState struct {
	State string
	Count int
}

