# AED_syslog_Scan
# README #
#
#Built-in keywords:
#Software Component .* is 'Crashing
#sync failed due to error
#crash
#fail
#error
#warning
#reboot
#invalid
#interrupt
#leak
#timeout
#blinky
#ipmi
#file_system
#database
#mce
#
# You can excluse or include keywords
#
# Usage examples:
#
# Basic run (only built-in keywords)
python AED_Syslog_Scan_v1.py --diag-path /path/to/diag_package
#
# Exclude some built-in categories
python AED_Syslog_Scan_v1.py --diag-path /diag --exclude-categories crash,fail,warning
#
# Add custom keywords
python AED_Syslog_Scan_v1.py --diag-path ./diag \
  --extra-keywords "kernel panic,oom killer,segfault,assertion failed"
#
# Combine exclude + extra keywords + custom output folder
python AED_Syslog_Scan_v1.py \
  --diag-path /home/user/diagnostics/latest \
  --output-dir /home/user/reports \
  --exclude-categories reboot,ipmi,mce \
  --extra-keywords "hung task,soft lockup,rcu stall"
#
# Very focused run – only custom keywords
python AED_Syslog_Scan_v1.py --diag-path ./diag \
  --exclude-categories software_component_crashing,sync_failed_due_to_error,crash,fail,error,warning,reboot,invalid,interrupt,leak,timeout,blinky,ipmi,file_system,database,mce \
  --extra-keywords "thermal throttle,critical temperature,overheat"
