package lib

// #cgo LDFLAGS: -ldl
// #include <stdlib.h>
// #include <dlfcn.h>
// #include <stdio.h>
// #include <strings.h>
// #include "KalkanCrypt.h"
//
// void getFunctionList(void *f) {
//     void (*KC_GetFunctionList)(stKCFunctionsType **);
//     KC_GetFunctionList = (void (*)(stKCFunctionsType **))f;
//     KC_GetFunctionList(&kc_funcs);
// }
//
// void setTSAUrl(char *tsaurl) {
//     kc_funcs->KC_TSASetUrl(tsaurl);
// }
//
// int init() {
//     int rv = (kc_funcs)->KC_Init();
//     return rv;
// }
import "C"

import (
	"fmt"
	"github.com/olegmlsn/mkc/config"
	"sync"
	"unsafe"
)

type MKC struct {
	Handle unsafe.Pointer
	Name   string
	Mtx    sync.Mutex
}

func (m *MKC) Init(opt config.Opt) error {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.dlopen func
	libName := C.CString(config.LibName)
	defer C.free(unsafe.Pointer(libName))

	handle := C.dlopen(libName, C.RTLD_LAZY)
	m.Handle = handle
	m.Name = config.LibName
	err := C.dlerror()
	if err != nil {
		return fmt.Errorf("lib: init: dlopen error: %s", C.GoString(err))
	}

	// C.dlsym func
	strFList := C.CString("KC_GetFunctionList")
	defer C.free(unsafe.Pointer(strFList))

	fList := C.dlsym(m.Handle, strFList)
	err = C.dlerror()
	if err != nil {
		fmt.Errorf("lib: init: dlsym error: %s", C.GoString(err))
	}

	// C.getFunctionList func
	C.getFunctionList(fList)
	err = C.dlerror()
	if err != nil {
		fmt.Errorf("lib: init: getFunctionList error: %s", C.GoString(err))
	}

	// C.init func
	rc := int(C.init())
	if rc != 0 {
		fmt.Errorf("lib: init: init error: %s", rc)
	}

	// C.setTSAUrl func
	strTSP := C.CString(opt.TSP)
	defer C.free(unsafe.Pointer(strTSP))

	C.setTSAUrl(
		strTSP,
	)
	err = C.dlerror()
	if err != nil {
		fmt.Errorf("lib: init: setTSAUrl error: %s", C.GoString(err))
	}

	return nil
}
