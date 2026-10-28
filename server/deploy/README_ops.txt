Install notes (NOT done; files only)
  useradd --system --home /opt/stealth --shell /usr/sbin/nologin stealth   (if absent)
  install -d -o stealth -g stealth -m 750 /opt/stealth/data-rh /opt/stealth/data-watch
  /opt/stealth/{stealth_indexer.py,relayer.mjs,chains.json,stealth_watch.py,node_modules->symlink,package.json} readable by user stealth
  install -m 600 -o stealth -g stealth rh.env /opt/stealth/rh.env ; watch.env likewise
  cp stealth-*.service stealth-watch.timer /etc/systemd/system/ ; systemctl daemon-reload
  systemctl enable --now stealth-indexer-rh stealth-relayer-rh stealth-watch.timer
  nginx: zones into http{} (see header of stealth-rh.conf), the locations into the app.deepyield.ai server{}; nginx -t && systemctl reload nginx
  Base units keep running untouched on 3873/3874; RH uses 3883/3884 and /opt/stealth/data-rh.
  Watchdog log of RH relayer = /opt/stealth/data-rh/relayer.rh.log (set STEALTH_RELAY_LOG above).
