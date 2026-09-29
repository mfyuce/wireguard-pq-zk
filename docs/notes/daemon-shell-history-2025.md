# General

```bash
./build.sh
watch 'sudo dmesg | grep wireguard | tail'
watch 'sudo genl ctrl list | grep -i wgzk'
watch 'sudo cat /sys/kernel/debug/wireguard/zk_pending | grep idx='
watch sudo cat /sys/kernel/debug/wireguard/zk_handshake
sudo ./target/debug/wg-zk-daemon daemon
cd ./run
sudo ./test_generic_single.sh 1


```
```bash
cargo run -- send-verify-ack  --peer-index <IDX>  --result 1  --family wgzk --version 1
```

# Misc

```bash
 1975  modinfo -F vermagic ~/wg-ext/wireguard.ko
 1976  modinfo -F vermagic ./drivers/net/wireguard/wireguard.ko 
 1977  uname -r
 1979  sudo dmesg | tail -n 30
1862  make -j$(nproc) modules
 1863  make menuconfig
 1864  make -j$(nproc) modules
 1873  sudo ls /sys/kernel/debug/wireguard/
 1874  sudo cat cat /sys/kernel/debug/wireguard/zk_handshake
 1875  sudo cat /sys/kernel/debug/wireguard/zk_handshake
 1890  make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
 1891  make menuconfig
 1892  make mrproper
 1893  cp /boot/config-$(uname -r) .config || true
 1894  make olddefconfig
 1895  make prepare modules_prepare
 1896  make -j"$(nproc)" M=drivers/net/wireguard modules
 1897  cp /boot/config-$(uname -r) .config
 1898  scripts/config --disable SYSTEM_TRUSTED_KEYS
 1899  scripts/config --disable SYSTEM_REVOCATION_KEYS
 1900  make olddefconfig
 1901  make modules_prepare
 1902  make modules -j$(nproc)
 1903  make modules -j$(nproc)make M=drivers/net/wireguard -j$(nproc) modules
 1904  make M=drivers/net/wireguard -j$(nproc) modules
 1905  sudo cp /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko /lib/modules/6.8.0-59-generic/kernel/drivers/net/wireguard/wireguard.ko
 1906  sudo modprobe wireguard
 1907  sudo dmesg 
 1908  uname -r
 1909  ls  /lib/modules/
 1910  sudo insmod /lib/modules/6.8.0-59-generic/kernel/drivers/net/wireguard/wireguard.ko
 1911  sudo dmesg | grep wgzk
 1912  sudo dmesg 
 1913  sudo depmod -a
 1914  sudo modprobe wireguard
 1915  sudo dmesg | grep wireguard
 1916  uname -r
 1917  readlink -f /boot/vmlinuz-$(uname -r)
 1918  dpkg-query -S $(readlink -f /boot/vmlinuz-$(uname -r))
 1919  SRCDIR="./tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0"
 1920  make -C /lib/modules/$(uname -r)/build M="$SRCDIR/drivers/net/wireguard" clean
 1921  make -C /lib/modules/$(uname -r)/build M="$SRCDIR/drivers/net/wireguard" modules
 1922  SRCDIR="/home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0"
 1923  make -C /lib/modules/$(uname -r)/build M="$SRCDIR/drivers/net/wireguard" modules
 1924  modinfo -F vermagic "$SRCDIR/drivers/net/wireguard/wireguard.ko"
 1925  sudo install -D -m 644 "$SRCDIR/drivers/net/wireguard/wireguard.ko"   /lib/modules/$(uname -r)/extra/wireguard.ko
 1926  sudo depmod -a
 1927  sudo modprobe wireguard
 1928  sudo dmesg | grep wireguard
 1929  cat /sys/kernel/debug/zk_pending
 1930  sudo cat /sys/kernel/debug/zk_pending
 1931  sudo cat /sys/kernel/debug/wireguard
 1932  sudo cat /sys/kernel/debug/wireguard/zk_pending
 1933  watch 'sudo cat /sys/kernel/debug/wireguard/zk_pending'
 1934  cd userspace/wg-zk-daemon/
 1935  cargo run -- send-verify-ack   --peer-index 1   --result 1   --family wgzk   --version 1
 1936  sudo genl ctrl getfamily name wgzk
 1937  sudo cargo run -- send-verify-ack   --peer-index 1   --result 1   --family wgzk   --version 1
 1938  sudo target/debug/wg-zk-daemon send-verify-ack   --peer-index 1   --result 1   --family wgzk   --version 1
 1939  sudo target/release/wg-zk-daemon send-verify-ack   --peer-index 1   --result 1   --family wgzk   --version 1
 1940  cd ~/work/projects/tmp/enes/wireguard-zk-handshake
 1941  ./build.sh 
 1942  clear
 1943  ./build.sh 
 1944  sudo dmesg | grep wireguard
 1945  sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko
 1946  sudo dmesg | grep wireguard
 1947  sudo rmmod wireguard
 1948  sudo dmesg | grep wireguard
 1949  sudo insmod /lib/modules/$(uname -r)/extra/wireguard.ko
 1950  sudo dmesg | grep wireguard
 1951  clear
 1952  ./build.sh 
 1953  sudo rmmod wireguard
 1954  sudo insmod /lib/modules/6.8.0-59-generic/extra/wireguard.ko
 1955  sudo install -D -m 644 /home/fatihyuce/work/projects/tmp/enes/wireguard-zk-handshake/tmp/linux-signed-hwe-6.8-6.8.0/linux-hwe-6.8-6.8.0/drivers/net/wireguard/wireguard.ko /lib/modules/6.8.0-59-generic/extra/wireguard.ko
 1956  sudo insmod /lib/modules/6.8.0-59-generic/extra/wireguard.ko
 1957  sudo dmesg | grep wireguard
 1958  ./build.sh 
 1959  sudo dmesg | grep wireguard
 1960  sudo dmesg 
 1961  sudo dmesg | grep wgzk
 1962  sudo dmesg | grep wireguard
 1963  sudo apt-get install -y libnl-utils
 1964  sudo genl ctrl list | grep -i wgzk
 1965  sudo cat /sys/kernel/debug/netlink/genetlink | grep -i wgzk
 1966  sudo cat /sys/kernel/debug/netlink/
 1967  sudo ls /sys/kernel/debug/netlink/
 1968  sudo ls /sys/kernel/debug
 1969  sudo genl ctrl getfamily name wgzk
 1970  sudo genl ctrl list 

```
