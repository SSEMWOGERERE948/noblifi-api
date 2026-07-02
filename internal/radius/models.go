package radius

import "time"

type RadCheck struct {
	ID        uint   `gorm:"primaryKey;column:id" json:"id"`
	Username  string `gorm:"column:username;index" json:"username"`
	Attribute string `gorm:"column:attribute" json:"attribute"`
	Op        string `gorm:"column:op" json:"op"`
	Value     string `gorm:"column:value" json:"value"`
}

func (RadCheck) TableName() string {
	return "radcheck"
}

type RadReply struct {
	ID        uint   `gorm:"primaryKey;column:id" json:"id"`
	Username  string `gorm:"column:username;index" json:"username"`
	Attribute string `gorm:"column:attribute" json:"attribute"`
	Op        string `gorm:"column:op" json:"op"`
	Value     string `gorm:"column:value" json:"value"`
}

func (RadReply) TableName() string {
	return "radreply"
}

type RadAcct struct {
	RadAcctID           uint       `gorm:"primaryKey;column:radacctid" json:"radacctid"`
	AcctSessionID       string     `gorm:"column:acctsessionid;index" json:"acctsessionid"`
	AcctUniqueID        string     `gorm:"column:acctuniqueid;uniqueIndex" json:"acctuniqueid"`
	Username            string     `gorm:"column:username;index" json:"username"`
	GroupName           string     `gorm:"column:groupname" json:"groupname"`
	Realm               string     `gorm:"column:realm" json:"realm"`
	NASIPAddress        string     `gorm:"column:nasipaddress" json:"nasipaddress"`
	NASPortID           string     `gorm:"column:nasportid" json:"nasportid"`
	NASPortType         string     `gorm:"column:nasporttype" json:"nasporttype"`
	AcctStartTime       *time.Time `gorm:"column:acctstarttime" json:"acctstarttime"`
	AcctUpdateTime      *time.Time `gorm:"column:acctupdatetime" json:"acctupdatetime"`
	AcctStopTime        *time.Time `gorm:"column:acctstoptime" json:"acctstoptime"`
	AcctInterval        *int       `gorm:"column:acctinterval" json:"acctinterval"`
	AcctSessionTime     *int       `gorm:"column:acctsessiontime" json:"acctsessiontime"`
	AcctAuthentic       string     `gorm:"column:acctauthentic" json:"acctauthentic"`
	ConnectInfoStart    string     `gorm:"column:connectinfo_start" json:"connectinfo_start"`
	ConnectInfoStop     string     `gorm:"column:connectinfo_stop" json:"connectinfo_stop"`
	AcctInputOctets     int64      `gorm:"column:acctinputoctets;default:0" json:"acctinputoctets"`
	AcctOutputOctets    int64      `gorm:"column:acctoutputoctets;default:0" json:"acctoutputoctets"`
	CalledStationID     string     `gorm:"column:calledstationid" json:"calledstationid"`
	CallingStationID    string     `gorm:"column:callingstationid;index" json:"callingstationid"`
	AcctTerminateCause  string     `gorm:"column:acctterminatecause" json:"acctterminatecause"`
	ServiceType         string     `gorm:"column:servicetype" json:"servicetype"`
	FramedProtocol      string     `gorm:"column:framedprotocol" json:"framedprotocol"`
	FramedIPAddress     string     `gorm:"column:framedipaddress" json:"framedipaddress"`
	FramedIPv6Address   string     `gorm:"column:framedipv6address" json:"framedipv6address"`
	FramedIPv6Prefix    string     `gorm:"column:framedipv6prefix" json:"framedipv6prefix"`
	FramedInterfaceID   string     `gorm:"column:framedinterfaceid" json:"framedinterfaceid"`
	DelegatedIPv6Prefix string     `gorm:"column:delegatedipv6prefix" json:"delegatedipv6prefix"`
}

func (RadAcct) TableName() string {
	return "radacct"
}

type NAS struct {
	ID          uint   `gorm:"primaryKey;column:id" json:"id"`
	NASName     string `gorm:"column:nasname;uniqueIndex" json:"nasname"`
	ShortName   string `gorm:"column:shortname" json:"shortname"`
	Type        string `gorm:"column:type;default:other" json:"type"`
	Ports       *int   `gorm:"column:ports" json:"ports"`
	Secret      string `gorm:"column:secret" json:"secret"`
	Server      string `gorm:"column:server" json:"server"`
	Community   string `gorm:"column:community" json:"community"`
	Description string `gorm:"column:description" json:"description"`
}

func (NAS) TableName() string {
	return "nas"
}
