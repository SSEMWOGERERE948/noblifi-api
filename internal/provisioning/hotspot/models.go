package hotspot

type PlanView struct {
	ID              string
	Name            string
	Price            int
	DurationMinutes  int
	DataLimitMB      int
	UploadSpeed      string
	DownloadSpeed    string
	MaxDevices       int
}

type PortalData struct {
	HotspotName string
	Plans       []PlanView
}