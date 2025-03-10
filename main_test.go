package main

import (
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/stretchr/testify/assert"
	"gopkg.in/ini.v1"
	"path/filepath"
	"testing"
)

func ptr(s string) *string {
	return &s
}

func TestUpdateAWSConfig_AddProfile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "test_config")

	cfg := ini.Empty()
	cfg.SaveTo(configPath)

	accountId := "123456789012"
	region := "us-east-1"
	startUrl := "https://mock-sso.awsapps.com/start"
	profileName := "mock-mockaccount"
	roleName := "AdministratorAccess"

	accounts := []types.AccountInfo{
		{
			AccountId:   ptr(accountId),
			AccountName: ptr("MockAccount"),
		},
		{
			AccountId:   ptr("123456789013"),
			AccountName: ptr("AnotherMockAccount"),
		},
	}

	opts.DryRun = false
	opts.Remove = false
	opts.RoleName = roleName
	err := updateAWSConfig(configPath, accounts, startUrl, region, "mock")
	assert.NoError(t, err)

	cfg, err = ini.Load(configPath)
	assert.NoError(t, err)
	section := cfg.Section(profileName)
	assert.True(t, cfg.HasSection(profileName))
	assert.Equal(t, startUrl, section.Key("sso_start_url").String())
	assert.Equal(t, region, section.Key("sso_region").String())
	assert.Equal(t, accountId, section.Key("sso_account_id").String())
	assert.Equal(t, roleName, section.Key("sso_role_name").String())
	assert.Equal(t, region, section.Key("region").String())
}

func TestUpdateAWSConfig_RemoveProfile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "test_config")

	accountId := "123456789012"
	region := "us-east-1"
	startUrl := "https://mock-sso.awsapps.com/start"
	profileName := "mock-mockaccount"
	roleName := "AdministratorAccess"

	cfg := ini.Empty()
	section, _ := cfg.NewSection(profileName)
	section.Key("sso_start_url").SetValue(startUrl)
	section.Key("sso_region").SetValue(region)
	section.Key("sso_account_id").SetValue(accountId)
	section.Key("sso_role_name").SetValue(roleName)
	section.Key("region").SetValue(region)
	cfg.SaveTo(configPath)

	accounts := []types.AccountInfo{
		{
			AccountId:   ptr(accountId),
			AccountName: ptr("MockAccount"),
		},
	}

	opts.DryRun = false
	opts.Remove = true
	opts.RoleName = roleName
	err := updateAWSConfig(configPath, accounts, startUrl, region, "mock")
	assert.NoError(t, err)

	cfg, err = ini.Load(configPath)
	assert.NoError(t, err)
	assert.False(t, cfg.HasSection(profileName))
}
