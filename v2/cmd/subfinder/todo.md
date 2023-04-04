panic: send on closed channel

goroutine 97 [running]:
github.com/projectdiscovery/subfinder/v2/pkg/subscraping/sources/binaryedge.(*Source).dispatcher.func2(0x1400001ee60, 0x140001362d0, 0x140000983c0)
	/Users/tarun/Codebase/subfinder/v2/pkg/subscraping/sources/binaryedge/binaryedge.go:129 +0x284
github.com/projectdiscovery/subfinder/v2/pkg/core.(*Task).Execute(0x1400001ee60, {0x1035a7c68, 0x140000a6000}, 0x140000983c0)
	/Users/tarun/Codebase/subfinder/v2/pkg/core/tasks.go:51 +0x1a8
github.com/projectdiscovery/subfinder/v2/pkg/core.(*Executor).worker(0x140000983c0, {0x1035a7c68, 0x140000a6000}, 0x0?)
	/Users/tarun/Codebase/subfinder/v2/pkg/core/executor.go:52 +0x6c
created by github.com/projectdiscovery/subfinder/v2/pkg/core.(*Executor).CreateWorkers
	/Users/tarun/Codebase/subfinder/v2/pkg/core/executor.go:36 +0x34
2023/03/17 01:39:47 exit status 2
