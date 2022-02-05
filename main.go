package main

import (
	"bytes"
	"context"
	"encoding/json"

	//"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"

	retry "github.com/avast/retry-go"

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
	httpClient http.Client
	token      azcore.AccessToken
	base       string
	vers       string
}

// Do adds the access token to Authorization header before calling graphClient.c.Do()
// graphClient.c.Do() uses the http.Client that is inside graphClient
func (c *graphClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token.Token))
	return c.httpClient.Do(req)
}

// NewGraphClient returns a *graphClient with a default http client and token set
func NewGraphClient(tok azcore.AccessToken) (*graphClient, error) {
	return &graphClient{
		httpClient: *http.DefaultClient,
		token:      tok,
		base:       "https://graph.microsoft.com",
		vers:       "beta",
	}, nil
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

type ImportedWindowsAutopilotDeviceIdentityState struct {
	DeviceImportStatus   string `json:"deviceImportStatus"`
	DeviceRegistrationID string `json:"deviceRegistrationId"`
	DeviceErrorCode      int    `json:"deviceErrorCode"`
	DeviceErrorName      string `json:"deviceErrorName"`
}

var (
	errStatusUnknown = fmt.Errorf("DeviceImportStatus is %q", "unknown")
)

type ImportedWindowsAutopilotDeviceIdentityResp struct {
	ODataContext string `json:"@odata.context"`
	ImportedWindowsAutopilotDeviceIdentity
}

func (c *graphClient) ConfirmRegistered(id string) (bool, error) {
	err := retry.Do(
		func() error {
			base := c.base
			vers := c.vers
			endpoint := fmt.Sprintf(
				"deviceManagement/importedWindowsAutopilotDeviceIdentities/%s",
				id,
			)
			url := fmt.Sprintf(
				"%s/%s/%s",
				base,
				vers,
				endpoint,
			)
			fmt.Println(url)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return errors.Wrapf(err, "crafting GET failed")
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.Do(req)
			if err != nil {
				return errors.Wrapf(err, "calling c.Do failed")
			}
			body, _ := ioutil.ReadAll(resp.Body)
			var identity struct {
				ODataContext      string                                      `json:"@odata.context"`
				ID                string                                      `json:"id"`
				ProductKey        string                                      `json:"productKey"`
				SerialNumber      string                                      `json:"serialNumber"`
				HardwareIdentifer string                                      `json:"hardwareIdentifier"`
				Model             string                                      `json:"model"`
				Manufacturer      string                                      `json:"manufacturer"`
				State             ImportedWindowsAutopilotDeviceIdentityState `json:"state"`
			}
			if err := json.Unmarshal(body, &identity); err != nil {
				return errors.Wrapf(err, "couldn't unmarhsal to identity")
			}
			fmt.Println(identity)
			if identity.State.DeviceImportStatus == "unknown" || identity.State.DeviceImportStatus == "" {
				return errStatusUnknown
			}
			fmt.Println(identity.State.DeviceImportStatus)
			return nil
		},
		retry.Delay(time.Second*30),
		retry.Attempts(uint(10)),
		// Fixed delay instead of exponential backoff
		retry.DelayType(retry.FixedDelay),
		retry.RetryIf(func(err error) bool {
			return err == errStatusUnknown
		}),
	)

	return err != errStatusUnknown, nil
}

func (c *graphClient) RegisterAutopilotDevice() (*bool, error) {
	cs, err := Win32CompSys()
	if err != nil {
		return nil, err
	}
	bios, err := Win32Bios()
	if err != nil {
		return nil, err
	}
	mdmInfo, err := MDMDevDetail()
	if err != nil {
		return nil, err
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
		return nil, err
	}
	req, _ := http.NewRequest("POST", "https://graph.microsoft.com/beta/deviceManagement/importedWindowsAutopilotDeviceIdentities/", bytes.NewBuffer(data))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	fmt.Println(resp.StatusCode)
	fmt.Println(resp.Status)
	var identity ImportedWindowsAutopilotDeviceIdentity
	if err := json.Unmarshal(body, &identity); err != nil {
		return nil, err
	}
	fmt.Println(identity)
	registered, err := c.ConfirmRegistered(identity.ID)
	if err != nil {
		return nil, err
	}

	return &registered, nil

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
			InteractiveCredential: false,
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
	registered, err := gc.RegisterAutopilotDevice()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Success? %v", *registered)

}
