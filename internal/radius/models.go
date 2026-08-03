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
