package radius

import "time"

// ---------------------------------------------------------
// RADCHECK
// Authentication/check attributes for individual users.
// Example:
// NF-xxxx | Cleartext-Password | := | NF-xxxx
// ---------------------------------------------------------

type RadCheck struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Username  string `gorm:"column:username;index;not null"`
	Attribute string `gorm:"column:attribute;not null"`
	Op        string `gorm:"column:op;not null"`
	Value     string `gorm:"column:value;not null"`
}

func (RadCheck) TableName() string {
	return "radcheck"
}

// ---------------------------------------------------------
// RADREPLY
// Reply attributes assigned directly to individual users.
// ---------------------------------------------------------

type RadReply struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Username  string `gorm:"column:username;index;not null"`
	Attribute string `gorm:"column:attribute;not null"`
	Op        string `gorm:"column:op;not null"`
	Value     string `gorm:"column:value;not null"`
}

func (RadReply) TableName() string {
	return "radreply"
}

// ---------------------------------------------------------
// RADGROUPCHECK
// Check attributes belonging to a package / RADIUS group.
// ---------------------------------------------------------

type RadGroupCheck struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	GroupName string `gorm:"column:groupname;index;not null"`
	Attribute string `gorm:"column:attribute;not null"`
	Op        string `gorm:"column:op;not null"`
	Value     string `gorm:"column:value;not null"`
}

func (RadGroupCheck) TableName() string {
	return "radgroupcheck"
}

// ---------------------------------------------------------
// RADGROUPREPLY
// Reply attributes belonging to a package / RADIUS group.
//
// Examples:
// Session-Timeout
// Mikrotik-Rate-Limit
// Port-Limit
// ---------------------------------------------------------

type RadGroupReply struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	GroupName string `gorm:"column:groupname;index;not null"`
	Attribute string `gorm:"column:attribute;not null"`
	Op        string `gorm:"column:op;not null"`
	Value     string `gorm:"column:value;not null"`
}

func (RadGroupReply) TableName() string {
	return "radgroupreply"
}

// ---------------------------------------------------------
// RADUSERGROUP
// Links a voucher/user to a RADIUS package/group.
// ---------------------------------------------------------

type RadUserGroup struct {
	Username  string `gorm:"column:username;index;not null"`
	GroupName string `gorm:"column:groupname;index;not null"`
	Priority  int    `gorm:"column:priority;default:1;not null"`
}

func (RadUserGroup) TableName() string {
	return "radusergroup"
}

// ---------------------------------------------------------
// RADPOSTAUTH
//
// FreeRADIUS writes authentication results here.
//
// Example:
//
// username      NF-9649a372
// pass          NF-9649a372
// reply         Access-Accept
// authdate      2026-07-26 ...
//
// Your FreeRADIUS configuration is currently executing:
//
// INSERT INTO radpostauth
// (username, pass, reply, authdate)
// VALUES (...)
//
// This table therefore MUST exist.
// ---------------------------------------------------------

type RadPostAuth struct {
	ID       int64     `gorm:"column:id;primaryKey;autoIncrement"`
	Username string    `gorm:"column:username;index;not null"`
	Pass     string    `gorm:"column:pass"`
	Reply    string    `gorm:"column:reply"`
	AuthDate time.Time `gorm:"column:authdate;index;not null;default:CURRENT_TIMESTAMP"`
}

func (RadPostAuth) TableName() string {
	return "radpostauth"
}

// ---------------------------------------------------------
// NAS / RADIUS accounting records
// ---------------------------------------------------------

type NAS struct {
	ID          int64  `gorm:"column:id;primaryKey;autoIncrement"`
	NASName     string `gorm:"column:nasname;uniqueIndex;not null"`
	ShortName   string `gorm:"column:shortname;not null"`
	Type        string `gorm:"column:type;not null;default:'other'"`
	Ports       *int   `gorm:"column:ports"`
	Secret      string `gorm:"column:secret;not null"`
	Server      string `gorm:"column:server"`
	Community   string `gorm:"column:community"`
	Description string `gorm:"column:description"`
}

func (NAS) TableName() string {
	return "nas"
}

type RadAcct struct {
	ID                  int64      `gorm:"column:radacctid;primaryKey;autoIncrement"`
	AcctSessionID       string     `gorm:"column:acctsessionid;not null"`
	AcctUniqueID        string     `gorm:"column:acctuniqueid;uniqueIndex;not null"`
	Username            string     `gorm:"column:username;not null"`
	GroupName           string     `gorm:"column:groupname;not null;default:''"`
	Realm               string     `gorm:"column:realm"`
	NASIPAddress        string     `gorm:"column:nasipaddress"`
	NASPortID           string     `gorm:"column:nasportid"`
	NASPortType         string     `gorm:"column:nasporttype"`
	AcctStartTime       *time.Time `gorm:"column:acctstarttime"`
	AcctUpdateTime      *time.Time `gorm:"column:acctupdatetime"`
	AcctStopTime        *time.Time `gorm:"column:acctstoptime"`
	AcctInterval        *int       `gorm:"column:acctinterval"`
	AcctSessionTime     *int       `gorm:"column:acctsessiontime"`
	AcctAuthentic       string     `gorm:"column:acctauthentic"`
	ConnectInfoStart    string     `gorm:"column:connectinfo_start"`
	ConnectInfoStop     string     `gorm:"column:connectinfo_stop"`
	AcctInputOctets     int64      `gorm:"column:acctinputoctets;default:0"`
	AcctOutputOctets    int64      `gorm:"column:acctoutputoctets;default:0"`
	CalledStationID     string     `gorm:"column:calledstationid"`
	CallingStationID    string     `gorm:"column:callingstationid"`
	AcctTerminateCause  string     `gorm:"column:acctterminatecause"`
	ServiceType         string     `gorm:"column:servicetype"`
	FramedProtocol      string     `gorm:"column:framedprotocol"`
	FramedIPAddress     string     `gorm:"column:framedipaddress"`
	FramedIPv6Address   string     `gorm:"column:framedipv6address"`
	FramedIPv6Prefix    string     `gorm:"column:framedipv6prefix"`
	FramedInterfaceID   string     `gorm:"column:framedinterfaceid"`
	DelegatedIPv6Prefix string     `gorm:"column:delegatedipv6prefix"`
}

func (RadAcct) TableName() string {
	return "radacct"
}
