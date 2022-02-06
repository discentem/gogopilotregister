package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"

	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/logger"

	"github.com/google/glazier/go/registry"

	"github.com/discentem/gogopilotregister/wmi"

	"github.com/pkg/errors"

	retry "github.com/avast/retry-go"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// graphClient lets you interact with MS Graph APIs: https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0
type graphClient struct {
	httpClient http.Client
	cred       *azidentity.ChainedTokenCredential
	token      *azcore.AccessToken
	options    graphClientOptions
}

type graphClientOptions struct {
	Base              string
	Vers              string
	TenantID          string
	ClientID          string
	Scopes            []string
	CredentialOptions graphCredentialOptions
}

type graphCredentialOptions struct {
	Interactive bool
}

// Do obtains a azcore.Accesstoken from c.cred, if necessary, and adds the token to Authorization header before calling graphClient.httpClient.Do().
func (c *graphClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.token == nil {
		token, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{
			Scopes:   c.options.Scopes,
			TenantID: c.options.TenantID,
		})
		if err != nil {
			return nil, err
		}
		c.token = token
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.token.Token))
	return c.httpClient.Do(req)
}

func Cred(ctx context.Context, tenantID, ClientID string, opts graphCredentialOptions) (*azidentity.ChainedTokenCredential, error) {
	credList := []azcore.TokenCredential{}
	if opts.Interactive {
		interactive, err := azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
			TenantID: tenantID,
			ClientID: clientID,
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
		TenantID: tenantID,
		ClientID: clientID,
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
	return chain, nil
}

// NewGraphClient returns a *graphClient with a default http client and token set
func NewGraphClient(ctx context.Context, opts graphClientOptions) (*graphClient, error) {

	cred, err := Cred(ctx, opts.TenantID, opts.ClientID, opts.CredentialOptions)
	if err != nil {
		return nil, err
	}

	if opts.CredentialOptions.Interactive {
		if err := registry.Create(`SOFTWARE\Policies\Microsoft\Edge`); err != nil {
			logger.Warning("could not create Edge key")
		}
		if err := registry.SetInteger(`SOFTWARE\Policies\Microsoft\Edge`, `HideFirstRunExperience`, 1); err != nil {
			logger.Warning("could not set HideFirstRunExperience")
		}
		logger.V(2).Info("HideFirstRunExperience = 1")
		if err := registry.SetInteger(`SOFTWARE\Policies\Microsoft\Edge`, `BrowserSignin`, 0); err != nil {
			logger.Warning("could not set BrowserSignin")
		}
		logger.V(2).Info("BrowserSignin = 0")

	}

	return &graphClient{
		httpClient: *http.DefaultClient,
		cred:       cred,
		token:      nil,
		options:    opts,
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

func (c *graphClient) ConfirmRegistered(ctx context.Context, id string) (bool, error) {
	err := retry.Do(
		func() error {
			endpoint := fmt.Sprintf("deviceManagement/importedWindowsAutopilotDeviceIdentities/%s", id)
			url := fmt.Sprintf(
				"%s/%s/%s",
				c.options.Base,
				c.options.Vers,
				endpoint,
			)
			fmt.Println(url)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return errors.Wrapf(err, "crafting GET failed")
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.Do(ctx, req)
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

func (c *graphClient) RegisterAutopilotDevice(ctx context.Context) (*bool, error) {
	cs, err := wmi.Win32CompSys()
	if err != nil {
		return nil, err
	}
	bios, err := wmi.Win32Bios()
	if err != nil {
		return nil, err
	}
	mdmInfo, err := wmi.MDMDevDetail()
	if err != nil {
		return nil, err
	}
	type AutopilotState struct {
		ODataType            string `json:"@odata.type"`
		DeviceImportStatus   string `json:"deviceImportStatus"`
		DeviceRegistrationID string `json:"deviceRegistrationId"`
		DeviceErrorCode      int    `json:"deviceErrorCode"`
		DeviceErrorName      string `json:"deviceErrorName"`
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
	resp, err := c.Do(ctx, req)
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
	registered, err := c.ConfirmRegistered(ctx, identity.ID)
	if err != nil {
		return nil, err
	}

	return &registered, nil

}

func main() {
	logLvl2 := flag.Bool("vv", false, "Sets log level")
	flag.Parse()

	defer logger.Init("gogopilotregister", true, true, ioutil.Discard).Close()
	if *logLvl2 {
		logger.SetLevel(2)
	}
	ctx := context.Background()
	gc, err := NewGraphClient(context.Background(),
		graphClientOptions{
			TenantID: tenantID,
			ClientID: clientID,
			CredentialOptions: graphCredentialOptions{
				Interactive: true,
			},
			Scopes: scopes,
		},
	)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	registered, err := gc.RegisterAutopilotDevice(ctx)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("Success? %v", *registered)

}
