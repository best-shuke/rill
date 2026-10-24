#!/bin/sh
# Runs inside the disposable router; exercise a rill-only login, not root ACLs.
set -eu
uci set rpcd.rill_review=login
uci set rpcd.rill_review.username=rill-review
uci set 'rpcd.rill_review.password=$p$root'
uci add_list rpcd.rill_review.read=luci-app-rill
uci add_list rpcd.rill_review.write=luci-app-rill
uci commit rpcd
/etc/init.d/rpcd restart
sleep 1
sid=$(ubus call session login '{"username":"rill-review","password":""}' | jsonfilter -e '@.ubus_rpc_session')
[ -n "$sid" ]
# uhttpd enforces the ubus transport ACL; rpcd additionally checks file paths.
rpc() {
    curl --noproxy '*' -fsS -H 'Content-Type: application/json' --data \
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$sid\",\"file\",\"$1\",$2]}" http://127.0.0.1/ubus
}
result=$(rpc exec '{"command":"/usr/libexec/rill-api","params":["GET","/version"]}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" = 0 ]
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" = 0 ]
result=$(rpc exec '{"command":"/bin/sh","params":["-c","true"]}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" != 0 ]
# file.write is intentionally unavailable: CGI upload cannot chmod a YAML
# payload executable. The exact config path is the only persistent write grant.
result=$(rpc write '{"path":"/etc/rill/config.yaml","data":"bad","mode":493}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" != 0 ]
curl --noproxy '*' -fsS --data-urlencode "sessionid=$sid" --data-urlencode 'path=/etc/rill/config.yaml' \
    http://127.0.0.1/cgi-bin/cgi-download > /tmp/rill-delegated-download
cmp /tmp/rill-delegated-download /etc/rill/config.yaml
printf 'rules: [MATCH,DIRECT]\n' > /tmp/rill-upload-source
curl --noproxy '*' -fsS -F "sessionid=$sid" -F filename=/tmp/rill-luci-check.yaml \
    -F filedata=@/tmp/rill-upload-source http://127.0.0.1/cgi-bin/cgi-upload > /tmp/rill-upload-result
cmp /tmp/rill-upload-source /tmp/rill-luci-check.yaml
result=$(rpc exec '{"command":"/usr/libexec/rill-validate","params":["check"]}')
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" = 0 ]
result=$(rpc exec '{"command":"/usr/libexec/rill-validate","params":["check","-v"]}')
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" != 0 ]
result=$(rpc exec '{"command":"/usr/libexec/rill-validate","params":["check -v"]}')
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" != 0 ]
result=$(rpc remove '{"path":"/tmp/rill-luci-check.yaml"}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" = 0 ]
uci delete rpcd.rill_review
uci commit rpcd
rm -f /tmp/rill-delegated-download /tmp/rill-upload-source /tmp/rill-upload-result
printf 'DELEGATED_OK\n'
