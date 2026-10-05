# caesar-link CLI mini demo, recorded against the live server.
# Re-render from SDKs/caesar-link-go:  vhs demo/demo.tape   (needs vhs, go, jq)
# Every share it creates is consumed or deleted before the recording ends.

Output demo/demo.gif

Set Shell "bash"
Set FontSize 17
Set Width 1280
Set Height 600
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 35ms
Set Framerate 24
Set WaitPattern /\$ ?$/
Set WaitTimeout 60s

# Build the CLI and stage two sample files in a scratch directory.
Hide
Type "export PS1='$ ' && go build -o /tmp/caesar-link-demo/caesar-link ./cmd/caesar-link && export PATH=/tmp/caesar-link-demo:$PATH"
Enter
Wait
Type "rm -rf /tmp/caesar-link-demo/work && mkdir -p /tmp/caesar-link-demo/work/received && cd /tmp/caesar-link-demo/work"
Enter
Wait
Type "echo DB_HOST=10.0.0.5 > deploy.env && echo DB_PASSWORD=hunter2 >> deploy.env && echo 'Rotate every 90 days.' > notes.md && clear"
Enter
Wait
Show

# 1) Burn after reading
Type "# 1) Burn after reading: sealed locally, the key lives only in the #fragment"
Enter
Type `URL=$(echo 'db password: hunter2' | caesar-link create -ttl 10m)`
Sleep 300ms
Enter
Wait
Type "echo $URL"
Enter
Wait
Sleep 1.5s
Type `caesar-link open "$URL"`
Sleep 300ms
Enter
Wait
Sleep 1s
Type `caesar-link open "$URL"    # once more`
Sleep 300ms
Enter
Wait
Sleep 3s

Ctrl+L
Sleep 300ms

# 2) Password mode
Type "# 2) Password: asked without echo, never on the command line"
Enter
Type `URL=$(echo 'API_TOKEN=demo-7f3a' | caesar-link create -ttl 10m -password)`
Sleep 300ms
Enter
Wait /Password:/
Sleep 400ms
Type "correct horse"
Enter
Wait /Repeat password:/
Sleep 300ms
Type "correct horse"
Enter
Wait
Sleep 1s
Type `caesar-link open "$URL"`
Sleep 300ms
Enter
Wait /Password:/
Sleep 400ms
Type "wrong guess"
Enter
Wait
Sleep 2.5s
Type `caesar-link open "$URL"`
Sleep 300ms
Enter
Wait /Password:/
Sleep 400ms
Type "correct horse"
Enter
Wait
Sleep 4s

Ctrl+L
Sleep 300ms

# 3) Files, scripting, revoke
Type "# 3) Files: unlimited views, JSON for scripts, revoke when done"
Enter
Type `caesar-link create -ttl 1h -views 0 -file deploy.env -file notes.md -json | tee share.json | jq`
Sleep 300ms
Enter
Wait
Sleep 1.5s
Type `URL=$(jq -r .url share.json); TOKEN=$(jq -r .deleteToken share.json)`
Sleep 300ms
Enter
Wait
Type `caesar-link open -out received "$URL"`
Sleep 300ms
Enter
Wait
Sleep 1s
Type `caesar-link info "$URL"`
Sleep 300ms
Enter
Wait
Sleep 2s
Type `caesar-link delete "$URL" "$TOKEN"`
Sleep 300ms
Enter
Wait
Sleep 1s
Type `caesar-link info "$URL"`
Sleep 300ms
Enter
Wait
Sleep 4s
