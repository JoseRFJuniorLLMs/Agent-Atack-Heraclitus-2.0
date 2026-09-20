* Log Fedora ao vivo: `SYSTEMD_COLORS=1 journalctl --user -fu heraclitus-attack-agent.service -o cat`
* Estado do serviço: `systemctl --user status heraclitus-attack-agent.service --no-pager -l`
* Painel operacional do banco: `cd /mnt/d/DEV/HeraclitusDB && ./target/release/heraclitus top`
