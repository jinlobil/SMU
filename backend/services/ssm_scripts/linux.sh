#!/bin/sh
# Read-only inventory. Optional product probes must never decide the script exit code.
export LC_ALL=C
quote() {
    printf '%s' "$1" | awk 'BEGIN { printf "\""; for(i=1;i<32;i++) ctl[sprintf("%c",i)]=i }
    NR>1 { printf "\\n" }
    { for(i=1;i<=length($0);i++) { c=substr($0,i,1); if(c=="\\" || c=="\"") printf "\\%s",c; else if(c in ctl) printf "\\u%04x",ctl[c]; else printf "%s",c } }
    END { printf "\"" }'
}
nullable() { if [ -n "$1" ]; then quote "$1"; else printf null; fi; }
web=''; was=''; db=''; seen=''; examined=''
add() {
    category=$1; product=$2; version=$3; path=$4; state=$5
    # Deduplicate multi-worker processes using product + installation path.
    key="|$category:$product:$path|"
    case "$seen" in *"$key"*) return;; esac
    seen="$seen$key"
    item="{\"product\":$(quote "$product"),\"version\":$(nullable "$version"),\"path\":$(nullable "$path"),\"status\":$(quote "$state") }"
    case "$category" in
        web) web="${web}${web:+,}${item}";;
        was) was="${was}${was:+,}${item}";;
        db) db="${db}${db:+,}${item}";;
    esac
}
extract_version() {
    text=$(cat)
    case "$text" in
        *Tengine/*) printf '%s' "$text" | sed -n 's@.*Tengine/\([0-9][0-9.]*\).*@\1@p';;
        *nginx/*) printf '%s' "$text" | sed -n 's@.*nginx/\([0-9][0-9.]*\).*@\1@p';;
        *Apache/*) printf '%s' "$text" | sed -n 's@.*Apache/\([0-9][0-9.]*\).*@\1@p';;
        *PostgreSQL*) printf '%s' "$text" | sed -n 's/.*PostgreSQL)[ ]*\([0-9][0-9.]*\).*/\1/p';;
        *' Ver '*) printf '%s' "$text" | sed -n 's/.* Ver \([0-9][0-9.]*\).*/\1/p';;
        *) printf '%s' "$text" | sed -n 's/.*[vV]ersion[ :v]*\([0-9][0-9.]*\).*/\1/p';;
    esac | head -n 1
}
probe_version() {
    # Only recognized server executables, with a hard per-probe time limit.
    command -v timeout >/dev/null 2>&1 || return 0
    timeout 2 "$1" "$2" 2>&1 | extract_version
}
host=$(hostname 2>/dev/null)
kernel=$(uname -r 2>/dev/null)
os_name=''; os_version=''
if [ -r /etc/os-release ]; then
    # os-release is a standard administrator-owned shell-compatible metadata file.
    . /etc/os-release
    os_name=${PRETTY_NAME:-${NAME:-}}; os_version=${VERSION_ID:-}
fi
if [ -z "$os_name" ] && [ -r /etc/redhat-release ]; then os_name=$(cat /etc/redhat-release); fi
if [ -z "$os_name" ]; then os_name=$(uname -s 2>/dev/null); fi
for proc in /proc/[0-9]*; do
    [ -r "$proc/comm" ] || continue
    comm=$(cat "$proc/comm" 2>/dev/null)
    case "$comm" in nginx|tengine|httpd|apache2|mysqld|mariadbd|postgres|postmaster|oracle|ora_pmon_*|sqlservr|mongod|redis-server|java) ;; *) continue;; esac
    exe=$(readlink "$proc/exe" 2>/dev/null)
    [ -n "$exe" ] || continue
    if [ "$comm" != java ]; then
        case "$examined" in *"|$exe|"*) continue;; esac
        examined="$examined|$exe|"
    fi
    cmd=$(tr '\000' ' ' < "$proc/cmdline" 2>/dev/null)
    case "$comm" in
        nginx|tengine)
            version_text=''; product=nginx
            if command -v timeout >/dev/null 2>&1; then
                version_text=$(timeout 2 "$exe" -v 2>&1)
                case "$version_text" in *Tengine*) product=Tengine;; esac
            fi
            version=$(printf '%s' "$version_text" | extract_version)
            add web "$product" "$version" "$exe" running;;
        httpd|apache2) add web Apache "$(probe_version "$exe" -v)" "$exe" running;;
        mysqld|mariadbd) product=MySQL; [ "$comm" != mariadbd ] || product=MariaDB
            add db "$product" "$(probe_version "$exe" --version)" "$exe" running;;
        postgres|postmaster) add db PostgreSQL "$(probe_version "$exe" --version)" "$exe" running;;
        oracle|ora_pmon_*) add db Oracle '' "$exe" running;;
        sqlservr) add db 'SQL Server' '' "$exe" running;;
        mongod) add db MongoDB "$(probe_version "$exe" --version)" "$exe" running;;
        redis-server) add db Redis '' "$exe" running;;
        java)
            case "$cmd" in
                *org.apache.catalina.startup.Bootstrap*|*-Dcatalina.base=*)
                    base=$(printf '%s' "$cmd" | sed -n 's/.*-Dcatalina.base=\([^ ]*\).*/\1/p')
                    version=''
                    if [ -r "$base/RELEASE-NOTES" ]; then
                        version=$(sed -n 's/.*Apache Tomcat Version \([0-9.]*\).*/\1/p' "$base/RELEASE-NOTES" | head -n 1)
                    fi
                    add was Tomcat "$version" "$base" running;;
                *weblogic.Server*) add was WebLogic '' "$(printf '%s' "$cmd" | sed -n 's/.*-Dweblogic.home=\([^ ]*\).*/\1/p')" running;;
                *org.jboss*|*jboss-modules*) add was JBoss '' "$(printf '%s' "$cmd" | sed -n 's/.*-Djboss.home.dir=\([^ ]*\).*/\1/p')" running;;
                *org.eclipse.jetty*) add was Jetty '' "$(printf '%s' "$cmd" | sed -n 's/.*-Djetty.home=\([^ ]*\).*/\1/p')" running;;
            esac;;
    esac
done
printf '{"hostname":%s,"kernel":%s,"os":%s,"os_version":%s,"os_install_date":null,"web":[%s],"was":[%s],"db":[%s]}\n' \
    "$(nullable "$host")" "$(nullable "$kernel")" "$(nullable "$os_name")" "$(nullable "$os_version")" "$web" "$was" "$db"
exit 0
