package radius

type RadCheck struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Username  string `gorm:"column:username;index"`
	Attribute string `gorm:"column:attribute"`
	Op        string `gorm:"column:op"`
	Value     string `gorm:"column:value"`
}

func (RadCheck) TableName() string {
	return "radcheck"
}

type RadReply struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	Username  string `gorm:"column:username;index"`
	Attribute string `gorm:"column:attribute"`
	Op        string `gorm:"column:op"`
	Value     string `gorm:"column:value"`
}

func (RadReply) TableName() string {
	return "radreply"
}

type RadGroupCheck struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	GroupName string `gorm:"column:groupname;index"`
	Attribute string `gorm:"column:attribute"`
	Op        string `gorm:"column:op"`
	Value     string `gorm:"column:value"`
}

func (RadGroupCheck) TableName() string {
	return "radgroupcheck"
}

type RadGroupReply struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement"`
	GroupName string `gorm:"column:groupname;index"`
	Attribute string `gorm:"column:attribute"`
	Op        string `gorm:"column:op"`
	Value     string `gorm:"column:value"`
}

func (RadGroupReply) TableName() string {
	return "radgroupreply"
}

type RadUserGroup struct {
	Username  string `gorm:"column:username;index"`
	GroupName string `gorm:"column:groupname;index"`
	Priority  int    `gorm:"column:priority"`
}

func (RadUserGroup) TableName() string {
	return "radusergroup"
}