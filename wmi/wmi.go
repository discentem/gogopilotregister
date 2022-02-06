package wmi

import (
	"errors"

	"github.com/StackExchange/wmi"
)

var (
	// ErrWMIEmptyResult indicates a condition where WMI failed to return the expected values.
	ErrWMIEmptyResult = errors.New("WMI returned without error, but zero results")
)

type Win32_Bios struct {
	SerialNumber string
}

func Win32Bios() (*Win32_Bios, error) {
	var result []Win32_Bios
	if err := wmi.Query(wmi.CreateQuery(&result, ""), &result); err != nil {
		return nil, err
	}
	if len(result) < 1 {
		return nil, ErrWMIEmptyResult
	}
	return &result[0], nil
}

type Win32_ComputerSystem struct {
	DNSHostName  string
	Domain       string
	DomainRole   int
	Model        string
	Manufacturer string
}

func Win32CompSys() (*Win32_ComputerSystem, error) {
	var result []Win32_ComputerSystem
	if err := wmi.Query(wmi.CreateQuery(&result, ""), &result); err != nil {
		return nil, err
	}
	if len(result) < 1 {
		return nil, ErrWMIEmptyResult
	}
	return &result[0], nil
}

type MDM_DevDetail_Ext01 struct {
	DeviceHardwareData string
}

func MDMDevDetail() (*MDM_DevDetail_Ext01, error) {
	var result []MDM_DevDetail_Ext01
	if err := wmi.QueryNamespace(wmi.CreateQuery(&result, ""), &result, "root/cimv2/mdm/dmmap"); err != nil {
		return nil, err
	}
	if len(result) < 1 {
		return nil, ErrWMIEmptyResult
	}
	return &result[0], nil
}
