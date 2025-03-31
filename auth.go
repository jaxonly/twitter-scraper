package twitterscraper

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"math/rand"
)

const (
	loginURL  = "https://api.twitter.com/1.1/onboarding/task.json"
	logoutURL = "https://api.twitter.com/1.1/account/logout.json"
	oAuthURL  = "https://api.twitter.com/oauth2/token"
	// Doesn't require x-client-transaction-id header in auth. x-rate-limit-limit: 2000
	bearerToken1 = "AAAAAAAAAAAAAAAAAAAAAFQODgEAAAAAVHTp76lzh3rFzcHbmHVvQxYYpTw%3DckAlMINMjmCwxUcaXbAN4XqJVdgMJaHqNOFgPMK0zN1qLqLQCF"
	// Requires x-client-transaction-id header in auth.
	bearerToken2      = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
	appConsumerKey    = "3nVuSoBZnx6U4vzUxf5w"
	appConsumerSecret = "Bcs59EFbbsdF6Sl9Ng71smgStWEGwXXKSjYvPVt7qys"
)

type (
	OpenAccount struct {
		OAuthToken       string `json:"oauth_token"`
		OAuthTokenSecret string `json:"oauth_token_secret"`
	}

	flow struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		FlowToken string `json:"flow_token"`
		Status    string `json:"status"`
		Subtasks  []struct {
			SubtaskID   string      `json:"subtask_id"`
			OpenAccount OpenAccount `json:"open_account"`
		} `json:"subtasks"`
	}

	profile struct {
		Id          int64       `json:"id"`
		IdStr       string      `json:"id_str"`
		Name        string      `json:"name"`
		ScreenName  string      `json:"screen_name"`
		Location    string      `json:"location"`
		Description string      `json:"description"`
		Url         interface{} `json:"url"`
		Entities    struct {
			Description struct {
				Urls []interface{} `json:"urls"`
			} `json:"description"`
		} `json:"entities"`
		Protected            bool        `json:"protected"`
		FollowersCount       int         `json:"followers_count"`
		FastFollowersCount   int         `json:"fast_followers_count"`
		NormalFollowersCount int         `json:"normal_followers_count"`
		FriendsCount         int         `json:"friends_count"`
		ListedCount          int         `json:"listed_count"`
		CreatedAt            string      `json:"created_at"`
		FavouritesCount      int         `json:"favourites_count"`
		UtcOffset            interface{} `json:"utc_offset"`
		TimeZone             interface{} `json:"time_zone"`
		GeoEnabled           bool        `json:"geo_enabled"`
		Verified             bool        `json:"verified"`
		StatusesCount        int         `json:"statuses_count"`
		MediaCount           int         `json:"media_count"`
		Lang                 interface{} `json:"lang"`
		Status               struct {
			CreatedAt string `json:"created_at"`
			Id        int64  `json:"id"`
			IdStr     string `json:"id_str"`
			Text      string `json:"text"`
			Truncated bool   `json:"truncated"`
			Entities  struct {
				Hashtags     []interface{} `json:"hashtags"`
				Symbols      []interface{} `json:"symbols"`
				UserMentions []struct {
					ScreenName string `json:"screen_name"`
					Name       string `json:"name"`
					Id         int64  `json:"id"`
					IdStr      string `json:"id_str"`
					Indices    []int  `json:"indices"`
				} `json:"user_mentions"`
				Urls  []interface{} `json:"urls"`
				Media []struct {
					Id            int64  `json:"id"`
					IdStr         string `json:"id_str"`
					Indices       []int  `json:"indices"`
					MediaUrl      string `json:"media_url"`
					MediaUrlHttps string `json:"media_url_https"`
					Url           string `json:"url"`
					DisplayUrl    string `json:"display_url"`
					ExpandedUrl   string `json:"expanded_url"`
					Type          string `json:"type"`
					OriginalInfo  struct {
						Width      int `json:"width"`
						Height     int `json:"height"`
						FocusRects []struct {
							X int `json:"x"`
							Y int `json:"y"`
							H int `json:"h"`
							W int `json:"w"`
						} `json:"focus_rects"`
					} `json:"original_info"`
					Sizes struct {
						Thumb struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"thumb"`
						Large struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"large"`
						Small struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"small"`
						Medium struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"medium"`
					} `json:"sizes"`
					Features struct {
						Large struct {
							Faces []interface{} `json:"faces"`
						} `json:"large"`
						Small struct {
							Faces []interface{} `json:"faces"`
						} `json:"small"`
						Medium struct {
							Faces []interface{} `json:"faces"`
						} `json:"medium"`
						Orig struct {
							Faces []interface{} `json:"faces"`
						} `json:"orig"`
					} `json:"features"`
				} `json:"media"`
			} `json:"entities"`
			ExtendedEntities struct {
				Media []struct {
					Id            int64  `json:"id"`
					IdStr         string `json:"id_str"`
					Indices       []int  `json:"indices"`
					MediaUrl      string `json:"media_url"`
					MediaUrlHttps string `json:"media_url_https"`
					Url           string `json:"url"`
					DisplayUrl    string `json:"display_url"`
					ExpandedUrl   string `json:"expanded_url"`
					Type          string `json:"type"`
					OriginalInfo  struct {
						Width      int `json:"width"`
						Height     int `json:"height"`
						FocusRects []struct {
							X int `json:"x"`
							Y int `json:"y"`
							H int `json:"h"`
							W int `json:"w"`
						} `json:"focus_rects"`
					} `json:"original_info"`
					Sizes struct {
						Thumb struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"thumb"`
						Large struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"large"`
						Small struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"small"`
						Medium struct {
							W      int    `json:"w"`
							H      int    `json:"h"`
							Resize string `json:"resize"`
						} `json:"medium"`
					} `json:"sizes"`
					Features struct {
						Large struct {
							Faces []interface{} `json:"faces"`
						} `json:"large"`
						Small struct {
							Faces []interface{} `json:"faces"`
						} `json:"small"`
						Medium struct {
							Faces []interface{} `json:"faces"`
						} `json:"medium"`
						Orig struct {
							Faces []interface{} `json:"faces"`
						} `json:"orig"`
					} `json:"features"`
					MediaKey string `json:"media_key"`
				} `json:"media"`
			} `json:"extended_entities"`
			Source                    string      `json:"source"`
			InReplyToStatusId         int64       `json:"in_reply_to_status_id"`
			InReplyToStatusIdStr      string      `json:"in_reply_to_status_id_str"`
			InReplyToUserId           int64       `json:"in_reply_to_user_id"`
			InReplyToUserIdStr        string      `json:"in_reply_to_user_id_str"`
			InReplyToScreenName       string      `json:"in_reply_to_screen_name"`
			Geo                       interface{} `json:"geo"`
			Coordinates               interface{} `json:"coordinates"`
			Place                     interface{} `json:"place"`
			Contributors              interface{} `json:"contributors"`
			IsQuoteStatus             bool        `json:"is_quote_status"`
			RetweetCount              int         `json:"retweet_count"`
			FavoriteCount             int         `json:"favorite_count"`
			Favorited                 bool        `json:"favorited"`
			Retweeted                 bool        `json:"retweeted"`
			PossiblySensitive         bool        `json:"possibly_sensitive"`
			PossiblySensitiveEditable bool        `json:"possibly_sensitive_editable"`
			Lang                      string      `json:"lang"`
			SupplementalLanguage      interface{} `json:"supplemental_language"`
		} `json:"status"`
		ContributorsEnabled            bool          `json:"contributors_enabled"`
		IsTranslator                   bool          `json:"is_translator"`
		IsTranslationEnabled           bool          `json:"is_translation_enabled"`
		ProfileBackgroundColor         string        `json:"profile_background_color"`
		ProfileBackgroundImageUrl      interface{}   `json:"profile_background_image_url"`
		ProfileBackgroundImageUrlHttps interface{}   `json:"profile_background_image_url_https"`
		ProfileBackgroundTile          bool          `json:"profile_background_tile"`
		ProfileImageUrl                string        `json:"profile_image_url"`
		ProfileImageUrlHttps           string        `json:"profile_image_url_https"`
		ProfileBannerUrl               string        `json:"profile_banner_url"`
		ProfileLinkColor               string        `json:"profile_link_color"`
		ProfileSidebarBorderColor      string        `json:"profile_sidebar_border_color"`
		ProfileSidebarFillColor        string        `json:"profile_sidebar_fill_color"`
		ProfileTextColor               string        `json:"profile_text_color"`
		ProfileUseBackgroundImage      bool          `json:"profile_use_background_image"`
		HasExtendedProfile             bool          `json:"has_extended_profile"`
		DefaultProfile                 bool          `json:"default_profile"`
		DefaultProfileImage            bool          `json:"default_profile_image"`
		PinnedTweetIds                 []interface{} `json:"pinned_tweet_ids"`
		PinnedTweetIdsStr              []interface{} `json:"pinned_tweet_ids_str"`
		HasCustomTimelines             bool          `json:"has_custom_timelines"`
		CanMediaTag                    bool          `json:"can_media_tag"`
		FollowedBy                     bool          `json:"followed_by"`
		Following                      bool          `json:"following"`
		FollowRequestSent              bool          `json:"follow_request_sent"`
		Notifications                  bool          `json:"notifications"`
		AdvertiserAccountType          string        `json:"advertiser_account_type"`
		AdvertiserAccountServiceLevels []interface{} `json:"advertiser_account_service_levels"`
		BusinessProfileState           string        `json:"business_profile_state"`
		TranslatorType                 string        `json:"translator_type"`
		WithheldInCountries            []interface{} `json:"withheld_in_countries"`
		Suspended                      bool          `json:"suspended"`
		NeedsPhoneVerification         bool          `json:"needs_phone_verification"`
		Email                          []struct {
			Address string `json:"address"`
			Current bool   `json:"current"`
			Status  string `json:"status"`
		} `json:"email"`
		Phone struct {
			Id            int64       `json:"id"`
			CreatedAt     string      `json:"created_at"`
			Address       string      `json:"address"`
			AddressForSms interface{} `json:"address_for_sms"`
			Verified      bool        `json:"verified"`
			EnabledFor    string      `json:"enabled_for"`
			Carrier       string      `json:"carrier"`
			CountryName   string      `json:"country_name"`
			CountryCode   string      `json:"country_code"`
			DeviceType    string      `json:"device_type"`
		} `json:"phone"`
		RequireSomeConsent bool `json:"require_some_consent"`
	}

	verifyCredentials struct {
		profile
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
)

func (s *Scraper) getAccessToken(consumerKey, consumerSecret string) (string, error) {
	req, err := http.NewRequest("POST", oAuthURL, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(consumerKey, consumerSecret)

	res, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, body)
	}

	var a struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return "", err
	}
	return a.AccessToken, nil
}

func (s *Scraper) getFlow(data map[string]interface{}) (*flow, error) {
	headers := http.Header{
		"Authorization":             []string{"Bearer " + s.bearerToken},
		"Content-Type":              []string{"application/json"},
		"User-Agent":                []string{s.userAgent},
		"X-Guest-Token":             []string{s.guestToken},
		"X-Twitter-Auth-Type":       []string{"OAuth2Client"},
		"X-Twitter-Active-User":     []string{"yes"},
		"X-Twitter-Client-Language": []string{"en"},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	s.setCSRFToken(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info flow
	err = json.NewDecoder(resp.Body).Decode(&info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func (s *Scraper) getFlowToken(data map[string]interface{}) (string, error) {
	info, err := s.getFlow(data)
	if err != nil {
		return "", err
	}

	if len(info.Errors) > 0 {
		return "", fmt.Errorf("auth error (%d): %v", info.Errors[0].Code, info.Errors[0].Message)
	}

	if len(info.Subtasks) > 0 {
		if info.Subtasks[0].SubtaskID == "LoginEnterAlternateIdentifierSubtask" {
			err = fmt.Errorf("auth error: %v", "LoginEnterAlternateIdentifierSubtask")
		} else if info.Subtasks[0].SubtaskID == "LoginAcid" {
			err = fmt.Errorf("auth error: %v", "LoginAcid")
		} else if info.Subtasks[0].SubtaskID == "LoginTwoFactorAuthChallenge" {
			err = fmt.Errorf("auth error: %v", "LoginTwoFactorAuthChallenge")
		} else if info.Subtasks[0].SubtaskID == "DenyLoginSubtask" {
			err = fmt.Errorf("auth error: %v", "DenyLoginSubtask")
		}
	}

	return info.FlowToken, err
}

// IsLoggedIn check if scraper logged in
func (s *Scraper) IsLoggedIn() bool {
	s.isLogged = true
	s.setBearerToken(bearerToken1)
	req, err := http.NewRequest("GET", "https://api.twitter.com/1.1/account/verify_credentials.json", nil)
	if err != nil {
		return false
	}
	var verify verifyCredentials
	err = s.RequestAPI(req, &verify)
	if err != nil || verify.Errors != nil {
		s.isLogged = false
		s.setBearerToken(bearerToken)
	} else {
		s.isLogged = true
		s.Profile = verify.profile
	}
	return s.isLogged
}

// randomDelay introduces a random delay between 1 and 3 seconds
func randomDelay() {
	delay := time.Duration(3000+rand.Intn(5000)) * time.Millisecond
	time.Sleep(delay)
}

// Login to Twitter
// Use Login(username, password) for ordinary login
// or Login(username, password, email) for login if you have email confirmation
// or Login(username, password, code_for_2FA) for login if you have two-factor authentication
func (s *Scraper) Login(credentials ...string) error {
	var username, password, confirmation string
	if len(credentials) < 2 || len(credentials) > 3 {
		return fmt.Errorf("invalid credentials")
	}

	username, password = credentials[0], credentials[1]
	if len(credentials) == 3 {
		confirmation = credentials[2]
	}

	s.setBearerToken(bearerToken2)

	err := s.GetGuestToken()
	if err != nil {
		return err
	}

	randomDelay()

	// flow start
	data := map[string]interface{}{
		"flow_name": "login",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
	}
	flowToken, err := s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow instrumentation step
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":         "LoginJsInstrumentationSubtask",
				"js_instrumentation": map[string]interface{}{"response": "{}", "link": "next_link"},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow username step
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": "LoginEnterUserIdentifierSSO",
				"settings_list": map[string]interface{}{
					"setting_responses": []map[string]interface{}{
						{
							"key":           "user_identifier",
							"response_data": map[string]interface{}{"text_data": map[string]interface{}{"result": username}},
						},
					},
					"link": "next_link",
				},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow password step
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":     "LoginEnterPassword",
				"enter_password": map[string]interface{}{"password": password, "link": "next_link"},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		return err
	}

	randomDelay()

	// flow duplication check
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id":              "AccountDuplicationCheck",
				"check_logged_in_account": map[string]interface{}{"link": "AccountDuplicationCheck_false"},
			},
		},
	}
	flowToken, err = s.getFlowToken(data)
	if err != nil {
		var confirmationSubtask string
		for _, subtask := range []string{"LoginAcid", "LoginTwoFactorAuthChallenge"} {
			if strings.Contains(err.Error(), subtask) {
				confirmationSubtask = subtask
				break
			}
		}
		if confirmationSubtask != "" {
			if confirmation == "" {
				return fmt.Errorf("confirmation data required for %v", confirmationSubtask)
			}

			randomDelay()

			// flow confirmation
			data = map[string]interface{}{
				"flow_token": flowToken,
				"subtask_inputs": []map[string]interface{}{
					{
						"subtask_id": confirmationSubtask,
						"enter_text": map[string]interface{}{"text": confirmation, "link": "next_link"},
					},
				},
			}
			_, err = s.getFlowToken(data)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	s.isLogged = true
	s.isOpenAccount = false
	return nil
}

// LoginOpenAccount as Twitter app
func (s *Scraper) LoginOpenAccount() (OpenAccount, error) {
	accessToken, err := s.getAccessToken(appConsumerKey, appConsumerSecret)
	if err != nil {
		return OpenAccount{}, err
	}
	s.setBearerToken(accessToken)

	err = s.GetGuestToken()
	if err != nil {
		return OpenAccount{}, err
	}

	// flow start
	data := map[string]interface{}{
		"flow_name": "welcome",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
	}
	flowToken, err := s.getFlowToken(data)
	if err != nil {
		return OpenAccount{}, err
	}

	// flow next link
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []interface{}{
			map[string]interface{}{
				"subtask_id": "NextTaskOpenLink",
			},
		},
	}
	info, err := s.getFlow(data)
	if err != nil {
		return OpenAccount{}, err
	}

	if len(info.Subtasks) > 0 {
		if info.Subtasks[0].SubtaskID == "OpenAccount" {
			s.oAuthToken = info.Subtasks[0].OpenAccount.OAuthToken
			s.oAuthSecret = info.Subtasks[0].OpenAccount.OAuthTokenSecret
			if s.oAuthToken == "" || s.oAuthSecret == "" {
				return OpenAccount{}, fmt.Errorf("auth error: %v", "Token or Secret is empty")
			}
			s.isLogged = true
			s.isOpenAccount = true
			return OpenAccount{
				OAuthToken:       info.Subtasks[0].OpenAccount.OAuthToken,
				OAuthTokenSecret: info.Subtasks[0].OpenAccount.OAuthTokenSecret,
			}, nil
		}
	}
	return OpenAccount{}, fmt.Errorf("auth error: %v", "OpenAccount")
}

func (s *Scraper) WithOpenAccount(openAccount OpenAccount) {
	s.oAuthToken = openAccount.OAuthToken
	s.oAuthSecret = openAccount.OAuthTokenSecret
	s.isLogged = true
	s.isOpenAccount = true
}

// Logout is reset session
func (s *Scraper) Logout() error {
	req, err := http.NewRequest("POST", logoutURL, nil)
	if err != nil {
		return err
	}
	err = s.RequestAPI(req, nil)
	if err != nil {
		return err
	}

	s.isLogged = false
	s.isOpenAccount = false
	s.guestToken = ""
	s.oAuthToken = ""
	s.oAuthSecret = ""
	s.client.Jar, _ = cookiejar.New(nil)
	s.setBearerToken(bearerToken)
	return nil
}

func (s *Scraper) GetCookies() []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookie := range s.client.Jar.Cookies(twURL) {
		if strings.Contains(cookie.Name, "guest") {
			continue
		}
		cookie.Domain = twURL.Host
		cookies = append(cookies, cookie)
	}
	return cookies
}

func (s *Scraper) SetCookies(cookies []*http.Cookie) {
	s.client.Jar.SetCookies(twURL, cookies)
}

func (s *Scraper) ClearCookies() {
	s.client.Jar, _ = cookiejar.New(nil)
}

// Use auth_token cookie as Token and ct0 cookie as CSRFToken
type AuthToken struct {
	Token     string
	CSRFToken string
}

// Auth using auth_token and ct0 cookies
func (s *Scraper) SetAuthToken(token AuthToken) {
	expires := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
	cookies := []*http.Cookie{{
		Name:       "auth_token",
		Value:      token.Token,
		Path:       "",
		Domain:     "twitter.com",
		Expires:    expires,
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	}, {
		Name:       "ct0",
		Value:      token.CSRFToken,
		Path:       "",
		Domain:     "twitter.com",
		Expires:    expires,
		RawExpires: "",
		MaxAge:     0,
		Secure:     false,
		HttpOnly:   false,
		SameSite:   0,
		Raw:        "",
		Unparsed:   nil,
	}}

	s.SetCookies(cookies)
}

func (s *Scraper) sign(method string, ref *url.URL) string {
	m := make(map[string]string)
	m["oauth_consumer_key"] = appConsumerKey
	m["oauth_nonce"] = "0"
	m["oauth_signature_method"] = "HMAC-SHA1"
	m["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	m["oauth_token"] = s.oAuthToken

	key := []byte(appConsumerSecret + "&" + s.oAuthSecret)
	h := hmac.New(sha1.New, key)

	query := ref.Query()
	for k, v := range m {
		query.Set(k, v)
	}

	req := []string{method, ref.Scheme + "://" + ref.Host + ref.Path, query.Encode()}
	var reqBuf bytes.Buffer
	for _, value := range req {
		if reqBuf.Len() > 0 {
			reqBuf.WriteByte('&')
		}
		reqBuf.WriteString(url.QueryEscape(value))
	}
	h.Write(reqBuf.Bytes())

	m["oauth_signature"] = base64.StdEncoding.EncodeToString(h.Sum(nil))

	var b bytes.Buffer
	for k, v := range m {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(v))
	}

	return "OAuth " + b.String()
}
