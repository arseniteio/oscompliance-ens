package firewall

import "testing"

func TestFirewallParsing(t *testing.T) {

	chains, err := nftChains(`{"nftables":[{"metainfo":{"version":"1.0.9"}},
{"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"chain":{"family":"ip","table":"nat","name":"post","handle":3,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"chain":{"family":"inet","table":"filter","name":"user_rules","handle":4}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 2 || chains[0].Policy != "drop" || chains[1].Hook != "forward" {
		t.Errorf("nft: %+v", chains)
	}

	ipt := iptablesChains("-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n", "ip")
	if len(ipt) != 2 || ipt[0].Policy != "accept" || ipt[1].Policy != "drop" {
		t.Errorf("iptables: %+v", ipt)
	}
}
