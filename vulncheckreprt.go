package reimage

type VulnCheckReportDataRejection struct {
	RejectedCVE
	Images []string
}

type VulnCheckReportData struct {
	Mappings      map[string]QualifiedImage
	Rejections    map[string]VulnCheckReportDataRejection
	UnusedIgnores []string
}
