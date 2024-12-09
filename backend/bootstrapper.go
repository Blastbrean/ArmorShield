package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	discordwebhook "github.com/bensch777/discord-webhook-golang"
	"github.com/shamaton/msgpack"
)

type bootstrapper struct {
	kr *Key
	pr *Project
	en string
}

type Action uint32

const (
	ACTION_BLACKLIST Action = iota
	ACTION_BOLO
)

func (bs bootstrapper) alert(sub *subscription, action Action) error {
	pr := bs.pr
	if pr == nil {
		return errors.New("project is not initialized")
	}

	kr := bs.kr
	if kr == nil {
		return errors.New("key is not initialized")
	}

	dd, err := kr.DiscordId()
	if err != nil {
		return err
	}

	embed := discordwebhook.Embed{
		Description: "Check Grafana Loki dashboard for more information.",
		Timestamp:   time.Now(),
		Footer: discordwebhook.Footer{
			Text: fmt.Sprintf("Subscription ID: '%s'", sub.uuid.String()),
		},
		Author: discordwebhook.Author{
			Name: fmt.Sprintf("PB Key ID & Discord ID (%s) (%s)", kr.Id, dd),
		},
	}

	if action == ACTION_BLACKLIST {
		embed.Title = "Automated 'Blacklist Key' Alert"
		embed.Color = 0xFAFF00
	}

	if action == ACTION_BOLO {
		embed.Title = "Automated 'Be On The Lookout' Alert"
		embed.Color = 0xFF0000
	}

	hook := discordwebhook.Hook{
		Content:  "@everyone",
		Username: "ArmorShield",
		Embeds:   []discordwebhook.Embed{embed},
	}

	payload, err := json.Marshal(hook)
	if err != nil {
		return err
	}

	return discordwebhook.ExecuteWebhook(pr.GetString("alertWebhook"), payload)
}

// NB: This function will close the connection.
func (bs bootstrapper) blacklist(sub *subscription, reason string) error {
	kr := bs.kr
	if kr == nil {
		return errors.New("key is not initialized")
	}

	kr.Set("blacklist", reason)

	err := sub.app.Save(kr)
	if err != nil {
		return err
	}

	bs.alert(sub, ACTION_BLACKLIST)

	return sub.close("you have been blacklisted")
}

func (bs bootstrapper) handle(sub *subscription, pk Packet) error {
	var br BootRequest
	err := msgpack.Unmarshal(pk.Msg, &br)
	if err != nil {
		return err
	}

	kr, err := FindKeyById(sub.app, br.KeyId)
	if err != nil {
		return sub.close("key not found")
	}

	di, err := kr.DiscordId()
	if err != nil {
		return sub.close(err.Error())
	}

	pr, err := kr.Project(sub.app)
	if err != nil {
		return sub.close(err.Error())
	}

	if kr.Expired(sub.timestamp) {
		return sub.close("key expired")
	}

	if kr.Blacklisted() {
		return sub.close("key blacklisted")
	}

	bs.kr = kr
	bs.pr = pr
	bs.en = br.ExploitName

	sub.logger = sub.logger.With(slog.String("discordId", di)).With(slog.String("keyId", kr.Id))
	sub.state.AddFlag(STATE_BOOTSTRAPPED)
	sub.handler = handshaker{hmac: [32]byte{}, rc4: [16]byte{}, bs: bs}
	sub.bootstrapper = &bs

	return sub.message(Message{Id: PacketIdBootstrap, Data: BootResponse{
		BaseTimestamp: uint64(sub.timestamp.Unix()),
		SubId:         sub.uuid,
	}})
}

func (bs bootstrapper) packet() byte {
	return PacketIdBootstrap
}

func (bs bootstrapper) state(sub *subscription) bool {
	return !sub.state.HasFlag(STATE_BOOTSTRAPPED)
}
