// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

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
