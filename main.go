package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/StackExchange/wmi"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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

type CredFlowOptions struct {
	TenantID              string
	ClientID              string
	Scopes                []string
	InteractiveCredential bool
}

type AutopilotState struct {
	ODataType            string `json:"@odata.type"`
	DeviceImportStatus   string `json:"deviceImportStatus"`
	DeviceRegistrationID string `json:"deviceRegistrationId"`
	DeviceErrorCode      int    `json:"deviceErrorCode"`
	DeviceErrorName      string `json:"deviceErrorName"`
}

type graphClient struct {
	c http.Client
	t azcore.AccessToken
	v string
}

// Do adds the access token to Authorization header before calling graphClient.c.Do()
// graphClient.c.Do() uses the http.Client that is inside graphClient
func (c *graphClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.t.Token))
	return c.c.Do(req)
}

// NewGraphClient returns a *graphClient with a default http client and token set
func NewGraphClient(tok azcore.AccessToken) (*graphClient, error) {
	return &graphClient{
		c: *http.DefaultClient,
		t: tok,
		v: "beta",
	}, nil
}

type ImportedWindowsAutopilotDeviceIdentityState struct {
	DeviceImportStatus   string `json:"deviceImportStatus"`
	DeviceRegistrationID string `json:"deviceRegistrationId"`
	DeviceErrorCode      int    `json:"deviceErrorCode"`
	DeviceErrorName      string `json:"deviceErrorName"`
}

type ImportedWindowsAutopilotDeviceIdentity struct {
	ID                        string                                      `json:"id"`
	GroupTag                  string                                      `json:"groupTag"`
	SerialNumber              string                                      `json:"serialNumber"`
	ProductKey                string                                      `json:"productKey"`
	ImportID                  string                                      `json:"importId"`
	HardwareIdentifier        string                                      `json:"hardwareIdentifier"`
	State                     ImportedWindowsAutopilotDeviceIdentityState `json:"state"`
	AssignedUserPrincipalName string                                      `json:"assignedUserPrincipalName"`
}

func (c *graphClient) AlreadyRegistered(serial string) (bool, error) {
	url := "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, nil
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return false, err
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var identites struct {
		Value []ImportedWindowsAutopilotDeviceIdentity `json:"value"`
	}
	if err := json.Unmarshal(body, &identites); err != nil {
		return false, err
	}
	alreadyRegistered := false
	for _, d := range identites.Value {
		if d.SerialNumber == serial {
			fmt.Println(d)
			alreadyRegistered = true
		}
	}
	return alreadyRegistered, nil
}

func (c *graphClient) RegisterAutopilotDevice() error {
	cs, err := Win32CompSys()
	if err != nil {
		return err
	}
	bios, err := Win32Bios()
	if err != nil {
		return err
	}
	mdmInfo, err := MDMDevDetail()
	if err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		ODataType         string         `json:"@odata.type"`
		SerialNumber      string         `json:"serialNumber"`
		HardwareIdentifer string         `json:"hardwareIdentifier"`
		Model             string         `json:"model"`
		Manufacturer      string         `json:"manufacturer"`
		State             AutopilotState `json:"state"`
	}{
		ODataType:         "#microsoft.graph.importedWindowsAutopilotDeviceIdentity",
		SerialNumber:      bios.SerialNumber,
		HardwareIdentifer: mdmInfo.DeviceHardwareData,
		Model:             strings.TrimSpace(cs.Model),
		Manufacturer:      strings.TrimSpace(cs.Manufacturer),
		State: AutopilotState{
			ODataType:          "microsoft.graph.importedWindowsAutopilotDeviceIdentityState",
			DeviceImportStatus: "pending",
			DeviceErrorCode:    0,
		},
	})
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("POST", "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities/", bytes.NewBuffer(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	_, err = c.Do(req)
	if err != nil {
		return err
	}
	return nil

}

func InitCredential(ctx context.Context, c *CredFlowOptions) (*azcore.AccessToken, error) {
	credList := []azcore.TokenCredential{}
	if c.InteractiveCredential {
		interactive, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
			TenantID: c.TenantID,
			ClientID: c.ClientID,
			// Need to configure as desktop app redirect, not web redirect
			// See https://github.com/Azure/azure-sdk-for-go/issues/16723#issuecomment-1004271528
			RedirectURL: "http://localhost:9090",
		})
		if err != nil {
			return nil, err
		}
		credList = append(credList, interactive)
	}
	// https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/device_code_credential.go
	deviceCode, err := azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
		TenantID: c.TenantID,
		ClientID: c.ClientID,
		// Customizes the UserPrompt. Replaces VerificationURL with shortlink.
		// Providing a custom UserPrompt can also allow the URL to be rewritten anywhere, instead of just stdout
		UserPrompt: func(ctx context.Context, deviceCodeMessage azidentity.DeviceCodeMessage) error {
			msg := strings.Replace(deviceCodeMessage.Message, "https://microsoft.com/devicelogin", "https://aka.ms/devicelogin", 1)
			fmt.Println(msg)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	credList = append(credList, deviceCode)
	chain, err := azidentity.NewChainedTokenCredential(
		credList,
		&azidentity.ChainedTokenCredentialOptions{},
	)
	if err != nil {
		return nil, err
	}
	token, err := chain.GetToken(ctx, policy.TokenRequestOptions{
		Scopes:   c.Scopes,
		TenantID: c.TenantID,
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func main() {
	token, err := InitCredential(
		context.Background(),
		&CredFlowOptions{
			TenantID:              tenantID,
			ClientID:              clientID,
			InteractiveCredential: true,
			Scopes:                scopes,
		},
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	gc, err := NewGraphClient(*token)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	bios, err := Win32Bios()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	registered, err := gc.AlreadyRegistered(bios.SerialNumber)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if !registered {
		if err := gc.RegisterAutopilotDevice(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

}
