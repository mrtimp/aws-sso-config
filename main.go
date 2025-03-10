package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"github.com/jessevdk/go-flags"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/sso/types"
	"gopkg.in/ini.v1"
)

type SSOToken struct {
	AccessToken string `json:"accessToken"`
	Region      string `json:"region"`
	StartURL    string `json:"startUrl"`
}

type Options struct {
	DryRun        bool   `long:"dry-run" description:"Print changes instead of modifying the AWS config file"`
	ProfilePrefix string `long:"profile-prefix" description:"The prefix to use on an AWS profile name (defaults to the start domain)"`
	Region        string `long:"region" description:"The region to use. Overrides config/env settings"`
	RoleName      string `short:"r" long:"role-name" description:"AWS role to generate configuration for" required:"true"`
	StartDomain   string `short:"s" long:"start-domain" description:"SSO start domain to generate configuration for" required:"true"`
	Remove        bool   `long:"remove" description:"Remove profiles that match the provided criteria"`
}

var opts Options

var (
	info    = color.New(color.FgBlue).SprintFunc()
	success = color.New(color.FgGreen).SprintFunc()
	warn    = color.New(color.FgYellow).SprintFunc()
	danger  = color.New(color.FgRed).SprintFunc()
)

func main() {
	_, err := flags.Parse(&opts)

	if err != nil {
		os.Exit(1)
	}

	token, err := readSSOToken()
	if err != nil {
		fmt.Println(danger("Error reading the SSO token:"), err)
		os.Exit(1)
	}

	region := token.Region
	if opts.Region != "" {
		region = opts.Region
	}

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		fmt.Println(danger("Error loading AWS config:"), err)
		os.Exit(1)
	}

	accounts, err := listSSOAccounts(cfg, token.AccessToken)
	if err != nil {
		fmt.Println(danger("Error listing accounts:"), err)
		os.Exit(1)
	}

	profilePrefix := opts.ProfilePrefix

	if opts.ProfilePrefix == "" {
		profilePrefix = ""
	}

	configPath := filepath.Join(os.Getenv("HOME"), ".aws", "config")

	err = updateAWSConfig(configPath, accounts, token.StartURL, region, profilePrefix)
	if err != nil {
		fmt.Println(danger("Error updating AWS config:"), err)
		os.Exit(1)
	}

	if opts.DryRun == false {
		fmt.Println(success("AWS SSO profiles updated successfully in ~/.aws/config"))
	}
}

func readSSOToken() (*SSOToken, error) {
	cacheDir := filepath.Join(os.Getenv("HOME"), ".aws", "sso", "cache")
	files, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, err
	}

	var selectedFile string
	var latestModTime int64

	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".json") {
			filePath := filepath.Join(cacheDir, file.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			var token SSOToken
			if err := json.Unmarshal(data, &token); err != nil {
				continue
			}

			if opts.StartDomain != "" && !strings.Contains(token.StartURL, opts.StartDomain) {
				continue
			}

			info, err := os.Stat(filePath)
			if err == nil && info.ModTime().Unix() > latestModTime {
				latestModTime = info.ModTime().Unix()
				selectedFile = filePath
			}
		}
	}

	if selectedFile == "" {
		return nil, fmt.Errorf(danger("Unable to find an AWS SSO token for domain %s"), opts.StartDomain)
	}

	data, err := os.ReadFile(selectedFile)
	if err != nil {
		return nil, err
	}

	var token SSOToken
	err = json.Unmarshal(data, &token)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func listSSOAccounts(cfg aws.Config, accessToken string) ([]types.AccountInfo, error) {
	client := sso.NewFromConfig(cfg)

	var accounts []types.AccountInfo
	var nextToken *string

	for {
		resp, err := client.ListAccounts(context.TODO(), &sso.ListAccountsInput{
			AccessToken: &accessToken,
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, account := range resp.AccountList {
			if opts.RoleName != "" {
				valid, err := validateRoleForAccount(client, accessToken, *account.AccountId)
				if err != nil {
					fmt.Printf(danger("Error validating role for account %s: %v\n", *account.AccountId), err)
					continue
				}

				if !valid {
					fmt.Printf(warn("Skipping account %s (%s): Role %s is not valid for the account\n"), *account.AccountName, *account.AccountId, opts.RoleName)
					continue
				}
			}
			accounts = append(accounts, account)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return accounts, nil
}

func validateRoleForAccount(client *sso.Client, accessToken, accountID string) (bool, error) {
	var nextToken *string
	for {
		resp, err := client.ListAccountRoles(context.TODO(), &sso.ListAccountRolesInput{
			AccessToken: &accessToken,
			AccountId:   &accountID,
			NextToken:   nextToken,
		})
		if err != nil {
			return false, err
		}

		for _, role := range resp.RoleList {
			if *role.RoleName == opts.RoleName {
				return true, nil
			}
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return false, nil
}

func updateAWSConfig(configPath string, accounts []types.AccountInfo, startURL, region string, profilePrefix string) error {
	cfg, err := ini.Load(configPath)
	if err != nil {
		return fmt.Errorf(danger("Failed to load AWS config file: %w"), err)
	}

	if profilePrefix != "" {
		profilePrefix = fmt.Sprintf("%s-", profilePrefix)
	}

	for _, account := range accounts {
		accountName := strings.ToLower(strings.TrimSpace(*account.AccountName))
		// @todo tidy up!
		accountName = strings.ReplaceAll(accountName, " ", "-")
		accountName = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				return r
			}
			return -1
		}, accountName)

		profileName := fmt.Sprintf("%s%s", profilePrefix, accountName)

		if opts.Remove {
			for _, section := range cfg.Sections() {
				if section.HasKey("sso_start_url") && section.HasKey("sso_account_id") &&
					section.HasKey("sso_role_name") && section.HasKey("region") {

					if section.Key("sso_start_url").String() == startURL &&
						section.Key("sso_account_id").String() == *account.AccountId &&
						section.Key("sso_role_name").String() == opts.RoleName &&
						section.Key("region").String() == region {

						fmt.Printf(info("Removing: ")+"%s\n", section.Name())

						if !opts.DryRun {
							cfg.DeleteSection(section.Name())
						}
					}
				}
			}
			continue
		}

		if opts.DryRun {
			fmt.Printf("%s\n", info("Running without dry run would add or update the following profile"))
			fmt.Printf("[profile %s]\n", profileName)
			fmt.Printf("sso_start_url = %s\n", startURL)
			fmt.Printf("sso_region = %s\n", region)
			fmt.Printf("sso_account_id = %s\n", *account.AccountId)
			fmt.Printf("sso_role_name = %s\n", opts.RoleName)
			fmt.Printf("region = %s\n\n", region)

			continue
		}

		section, err := cfg.GetSection(profileName)
		if err != nil {
			section, err = cfg.NewSection(profileName)
			if err != nil {
				return err
			}
		}

		section.Key("sso_start_url").SetValue(startURL)
		section.Key("sso_region").SetValue(region)
		section.Key("sso_account_id").SetValue(*account.AccountId)
		section.Key("sso_role_name").SetValue(opts.RoleName)
		section.Key("region").SetValue(region)
	}

	if opts.DryRun {
		fmt.Println(info("Dry run enabled, no changes were made"))
		return nil
	}

	return cfg.SaveTo(configPath)
}
