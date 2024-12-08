package main

// The message format that the server expects from the client.
type Packet struct {
	Id  byte
	Msg []byte
}

// A internal packet with an object instead of a byte slice.
type Message struct {
	Id   byte
	Data interface{}
}

// A handler for the packets.
type handler interface {
	// Handle a packet.
	handle(sub *subscription, pk Packet) error

	// Which ID is handled.
	packet() byte

	// Check if state is valid.
	state(sub *subscription) bool
}

const (
	PacketIdBootstrap = iota
	PacketIdHandshake
	PacketIdIdentify
	PacketIdLoad
	PacketIdDropping
	PacketIdKeyUpdate
	PacketIdHeartbeat
)

type BootRequest struct {
	KeyId       string
	ExploitName string
}

type BootResponse struct {
	BaseTimestamp uint64
	SubId         [16]byte
}

type HandshakeRequest struct {
	ClientPublicKey [32]byte
}

type HandshakeResponse struct {
	ServerPublicKey [32]byte
}

type AnalyticsInfo struct {
	SystemLocaleId      string
	OutputDevices       []string
	InputDevices        []string
	HasHyperion         bool
	HasTouchscreen      bool
	HasGyroscope        bool
	GpuMemory           int64
	Timezone            string
	Region              string
	DaylightSavingsTime bool
}

type FingerprintInfo struct {
	DeviceType  byte
	ExploitHwid string
}

type SessionInfo struct {
	CpuStart        float64
	PlaySessionId   string
	RobloxSessionId string
	RobloxClientId  string
	WorkspaceScan   []string
	LogHistory      []string
}

type JoinInfo struct {
	UserId        int
	PlaceId       int
	UserGroups    []uint64
	UserFollowing []uint64
	UserFriends   []uint64
}

type VersionInfo struct {
	RobloxClientChannel string
	RobloxClientGitHash string
	RobloxVersion       string
	CoreScriptVersion   string
	LuaVersion          string
}

type SubInfo struct {
	JoinInfo    JoinInfo
	SessionInfo SessionInfo
	VersionInfo VersionInfo
}

type KeyInfo struct {
	AnalyticsInfo   AnalyticsInfo
	FingerprintInfo FingerprintInfo
}

type IdentifyRequest struct {
	KeyInfo KeyInfo
	SubInfo SubInfo
}

type IdentifyResponse struct {
	CurrentRole string
}

type LoadRequest struct {
	GameId uint64
}

type LoadResponse struct {
	ScriptId string
}

type DropPacket struct {
	Reason string
}

type KeyUpdatePacket struct {
	Role string
}
