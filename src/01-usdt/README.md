# usdt 无需btf的挂载方式
使用前在项目根路径执行 git submodule update --init --recursive 把所有的submodule下载下来
然后可以cd到01-usdt中 进行make得到./dtraceattach程序
cd到./test/中进行make得到./test程序
执行./test程序后 再按照./dtraceattach的说明进行bpf挂载。

