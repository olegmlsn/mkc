package mkc

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
//
// int loadKeyStore(int storage, char *password, int passLen, char *container, int containerLen, char *alias) {
//     return kc_funcs->KC_LoadKeyStore(storage, password, passLen, container, containerLen, alias);
//}
//
// int x509ExportCertificateFromStore(char *alias, int flag, char *outCert, int *outCertLength) {
//     return kc_funcs->X509ExportCertificateFromStore(alias, flag, outCert, outCertLength);
// }
//
// int x509CertificateGetInfo(char *inCert, int inCertLength, int propId, char *outData, int *outDataLength) {
//     return kc_funcs->X509CertificateGetInfo(inCert, inCertLength, propId, (unsigned char*)outData, outDataLength);
// }
//
// unsigned long signData(char *alias, int flag, char *inData, int inDataLength, unsigned char *inSign, int inSignLen, unsigned char *outSign, int *outSignLength) {
//     bzero(outSign, *outSignLength);
//     return kc_funcs->SignData(alias, flag, inData, inDataLength, inSign, inSignLen, outSign, outSignLength);
// }
//
// unsigned long signXML(char *alias, int flags, char *inData, int inDataLength, unsigned char *outSign, int *outSignLength, char *signNodeId, char *parentSignNode, char *parentNameSpace) {
//     return kc_funcs->SignXML(alias, flags, inData, inDataLength, outSign, outSignLength, signNodeId, parentSignNode, parentNameSpace);
// }
//
// unsigned long hashData(char *algorithm, int flags, char *inData, int inDataLength, unsigned char *outData, int *outDataLength) {
//     bzero(outData, *outDataLength);
//     return kc_funcs->HashData(algorithm, flags, inData, inDataLength, outData, outDataLength);
// }
//
// unsigned long signHash(char *alias, int flags, char *inHash, int inHashLength, unsigned char *outSign, int *outSignLength) {
//     bzero(outSign, *outSignLength);
//     return kc_funcs->SignHash(alias, flags, inHash, inHashLength, outSign, outSignLength);
// }
//
// unsigned long verifyXML(char *alias, int flags, char *inData, int inDataLength, char *outVerifyInfo, int *outVerifyInfoLen) {
// 	   return kc_funcs->VerifyXML(alias, flags, inData, inDataLength, outVerifyInfo, outVerifyInfoLen);
// }
//
// unsigned long verifyData(char *alias, int flags, char *inData, int inDataLength, unsigned char *inoutSign, int inoutSignLength, char *outData, int *outDataLen, char *outVerifyInfo, int *outVerifyInfoLen, int inCertID, char *outCert, int *outCertLength) {
//    return kc_funcs->VerifyData(alias, flags, inData, inDataLength, inoutSign, inoutSignLength, outData, outDataLen, outVerifyInfo, outVerifyInfoLen, inCertID, outCert, outCertLength);
// }
import "C"

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"unsafe"
)

type MKC struct {
	Handle unsafe.Pointer
	Name   string
	Mtx    sync.Mutex
}

func (m *MKC) Init(opt Opt) error {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.dlopen func
	libName := C.CString(LibName)
	defer C.free(unsafe.Pointer(libName))

	handle := C.dlopen(libName, C.RTLD_LAZY)
	m.Handle = handle
	m.Name = LibName
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
		return fmt.Errorf("lib: init: dlsym error: %s", C.GoString(err))
	}

	// C.getFunctionList func
	C.getFunctionList(fList)
	err = C.dlerror()
	if err != nil {
		return fmt.Errorf("lib: init: getFunctionList error: %s", C.GoString(err))
	}

	// C.init func
	rc := int(C.init())
	if rc != 0 {
		return fmt.Errorf("lib: init: init error: %s", rc)
	}

	// C.setTSAUrl func
	strTSP := C.CString(opt.TSP)
	defer C.free(unsafe.Pointer(strTSP))

	C.setTSAUrl(
		strTSP,
	)
	err = C.dlerror()
	if err != nil {
		return fmt.Errorf("lib: init: setTSAUrl error: %s", C.GoString(err))
	}

	return nil
}

func (m *MKC) LoadCert(cert []byte, passwd string, alias string) error {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	tmpCert, err := os.CreateTemp("", "tmp.cert.*.p12")
	if err != nil {
		return fmt.Errorf("lib: loadCert: CreateTemp error: %s", err)
	}

	fName := tmpCert.Name()

	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			log.Printf("lib: loadCert: os.Remove error: %s", err)
		}
	}(fName)
	defer func(tmpCert *os.File) {
		err := tmpCert.Close()
		if err != nil {
			log.Printf("lib: loadCert: file close error: %s", err)
		}
	}(tmpCert)

	written, err := io.Copy(tmpCert, bytes.NewReader(cert))
	if err != nil {
		return fmt.Errorf("lib: loadCert: ioCopy error: %s", err)
	}

	if exp := int64(len(cert)); exp != written {
		return fmt.Errorf("lib: loadCert: integrity error %w: expected %d, written %d", exp, written)
	}

	// C.loadKeyStore func
	cPassword := C.CString(passwd)
	defer C.free(unsafe.Pointer(cPassword))

	cContainer := C.CString(fName)
	defer C.free(unsafe.Pointer(cContainer))

	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))

	rc := int(C.loadKeyStore(
		C.int(KCST_PKCS12), cPassword, C.int(len(passwd)),
		cContainer, C.int(len(fName)), cAlias,
	))
	if rc != 0 {
		return fmt.Errorf("lib: loadCert: loadKeyStore error: %s", rc)
	}
	return nil
}

func (m *MKC) ExportCert(alias string) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.x509ExportCertificateFromStore func
	flg := 0
	outCertLen := 32768

	outCert := C.malloc(C.ulong(C.sizeof_char * outCertLen))
	defer C.free(outCert)

	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))

	rc := int(C.x509ExportCertificateFromStore(
		cAlias,
		C.int(flg),
		(*C.char)(outCert),
		(*C.int)(unsafe.Pointer(&outCertLen)),
	))
	if rc != 0 {
		return "", fmt.Errorf("lib: exportCert: x509ExportCertificateFromStore error: %s", rc)
	}

	result := C.GoString((*C.char)(outCert))
	return result, nil
}

func (m *MKC) CertGetInfo(inCert string, pFlag int) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.x509CertificateGetInfo func
	cInCert := C.CString(inCert)
	defer C.free(unsafe.Pointer(cInCert))

	outDataLength := 32768
	outData := C.malloc(C.ulong(C.sizeof_char * outDataLength))
	defer C.free(outData)

	rc := int(C.x509CertificateGetInfo(
		cInCert,
		C.int(len(inCert)),
		C.int(pFlag),
		(*C.char)(outData),
		(*C.int)(unsafe.Pointer(&outDataLength)),
	))

	if rc != 0 {
		if val, ok := KcErrors[rc]; ok {
			if flg, ok := CertPropMap[pFlag]; ok {
				return "", fmt.Errorf("lib: certGetInfo: x509CertificateGetInfo error: %s %s", val, flg)
			}
			return "", fmt.Errorf("lib: certGetInfo: x509CertificateGetInfo error: %s", val)
		}
		return "", fmt.Errorf("lib: certGetInfo: x509CertificateGetInfo error: %s", rc)
	}

	result := C.GoString((*C.char)(outData))
	return result, nil
}

func (m *MKC) AllCertInfo(inCert string) (map[string]string, error) {
	result := make(map[string]string)
	for flg, fName := range CertPropMap {
		value, err := m.CertGetInfo(inCert, flg)
		if err != nil {
			continue
			//return nil, err
		}
		if value != "" {
			result[fName] = value
		}
	}
	return result, nil
}

func (m *MKC) SignData(data string, alias string, flg int) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.signData func
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))

	inData := C.CString(data)
	defer C.free(unsafe.Pointer(inData))
	inDataLength := len(data)

	inSign := ""

	outSignLength := 50000 + 2*inDataLength
	outSign := C.malloc(C.ulong(C.sizeof_uchar * outSignLength))
	defer C.free(outSign)

	kcInSignLength := len(inSign)
	kcInSign := unsafe.Pointer(C.CString(inSign))
	defer C.free(kcInSign)

	rc := int(C.signData(
		cAlias,
		C.int(flg),
		inData,
		C.int(inDataLength),
		(*C.uchar)(kcInSign),
		C.int(kcInSignLength),
		(*C.uchar)(outSign),
		(*C.int)(unsafe.Pointer(&outSignLength)),
	))

	if rc != 0 {
		return "", fmt.Errorf("lib: signData: signData error: %s", rc)
	}

	result := C.GoString((*C.char)(outSign))
	return result, nil

}

func (m *MKC) SignXML(data string, alias string, flg int) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.signXML func
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))

	cInData := C.CString(data)
	defer C.free(unsafe.Pointer(cInData))

	inDataLength := len(data)
	outSignLength := 50000 + inDataLength
	outSign := C.malloc(C.ulong(C.sizeof_uchar * outSignLength))
	defer C.free(outSign)

	signNodeID := ""
	cSignNodeID := C.CString(signNodeID)
	defer C.free(unsafe.Pointer(cSignNodeID))

	parentSignNode := ""
	cParentSignNode := C.CString(parentSignNode)
	defer C.free(unsafe.Pointer(cParentSignNode))

	parentNameSpace := ""
	cParentNameSpace := C.CString(parentNameSpace)
	defer C.free(unsafe.Pointer(cParentNameSpace))

	rc := int(C.signXML(
		cAlias,
		C.int(flg),
		cInData,
		C.int(inDataLength),
		(*C.uchar)(outSign),
		(*C.int)(unsafe.Pointer(&outSignLength)),
		cSignNodeID,
		cParentSignNode,
		cParentNameSpace,
	))

	if rc != 0 {
		if val, ok := KcErrors[rc]; ok {
			return "", fmt.Errorf("lib: SignXML: signXML error: %s", val)
		}
		return "", fmt.Errorf("lib: SignXML: signXML error: %s", rc)
	}

	result := C.GoString((*C.char)(outSign))
	return result, nil
}

func (m *MKC) HashData(data string, alg string, flg int) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.hashData func
	kcAlgo := C.CString(alg)
	defer C.free(unsafe.Pointer(kcAlgo))

	kcInData := C.CString(data)
	defer C.free(unsafe.Pointer(kcInData))
	inDataLength := len(data)

	outDataLength := 50000 + 2*inDataLength
	outData := C.malloc(C.ulong(C.sizeof_uchar * outDataLength))
	defer C.free(outData)

	rc := int(C.hashData(
		kcAlgo,
		C.int(flg),
		kcInData,
		C.int(inDataLength),
		(*C.uchar)(outData),
		(*C.int)(unsafe.Pointer(&outDataLength)),
	))

	if rc != 0 {
		if val, ok := KcErrors[rc]; ok {
			return "", fmt.Errorf("lib: HashData: hashData error: %s", val)
		}
		return "", fmt.Errorf("lib: HashData: hashData error: %s", rc)
	}

	result := C.GoString((*C.char)(outData))
	return result, nil
}

func (m *MKC) SignHash(data string, alias string, flg int) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.signHash func
	kcAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(kcAlias))

	kcInHash := C.CString(data)
	defer C.free(unsafe.Pointer(kcInHash))
	inHashLength := len(data)

	outSignLength := 50000 + 2*inHashLength
	outSign := C.malloc(C.ulong(C.sizeof_uchar * outSignLength))
	defer C.free(outSign)

	rc := int(C.signHash(
		kcAlias,
		C.int(flg),
		kcInHash,
		C.int(inHashLength),
		(*C.uchar)(outSign),
		(*C.int)(unsafe.Pointer(&outSignLength)),
	))

	if rc != 0 {
		if val, ok := KcErrors[rc]; ok {
			return "", fmt.Errorf("lib: SignHash: signHash error: %s", val)
		}
		return "", fmt.Errorf("lib: SignHash: signHash error: %s", rc)
	}

	result := C.GoString((*C.char)(outSign))
	return result, nil
}

func (m *MKC) VerifyXML(data string, alias string, flg int) (string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.verifyXML func
	cAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(cAlias))

	inData := C.CString(data)
	defer C.free(unsafe.Pointer(inData))

	inDataLength := len(data)
	outVerifyInfoLen := 64768
	outVerifyInfo := C.malloc(C.ulong(C.sizeof_char * outVerifyInfoLen))
	defer C.free(outVerifyInfo)

	rc := int(C.verifyXML(
		cAlias,
		C.int(flg),
		inData,
		C.int(inDataLength),
		(*C.char)(outVerifyInfo),
		(*C.int)(unsafe.Pointer(&outVerifyInfoLen)),
	))

	if rc != 0 {
		if val, ok := KcErrors[rc]; ok {
			return "", fmt.Errorf("lib: VerifyXML: verifyXML error: %s", val)
		}
		return "", fmt.Errorf("lib: VerifyXML: verifyXML error: %s", rc)
	}

	result := C.GoString((*C.char)(outVerifyInfo))
	return result, nil
}

func (m *MKC) VerifyData(data string, sign string, alias string, flg int) ([]string, error) {
	m.Mtx.Lock()
	defer m.Mtx.Unlock()

	// C.verifyData func
	const (
		outCertLength       = 64768
		outVerifyInfoLength = 64768
		outDataLength       = 28000
	)

	kcAlias := C.CString(alias)
	defer C.free(unsafe.Pointer(kcAlias))

	kcInData := C.CString(data)
	defer C.free(unsafe.Pointer(kcInData))
	inDataLength := len(data)

	kcInSign := unsafe.Pointer(C.CString(sign))
	defer C.free(kcInSign)
	inputSignLength := len(sign)

	var kcOutData [outDataLength]byte
	//kcOutData := C.malloc(C.ulong(C.sizeof_char * outDataLength))
	//defer C.free(kcOutData)
	kcOutDataLen := outDataLength

	var kcOutVerifyInfo [outVerifyInfoLength]byte
	//kcOutVerifyInfo := C.malloc(C.ulong(C.sizeof_char * outVerifyInfoLength))
	//defer C.free(kcOutVerifyInfo)
	kcOutVerifyInfoLen := outVerifyInfoLength

	kcInCertID := 0

	var kcOutCert [outCertLength]byte
	//kcOutCert := C.malloc(C.ulong(C.sizeof_char * outCertLength))
	//defer C.free(kcOutCert)
	kcOutCertLen := outCertLength

	rc := int(C.verifyData(
		kcAlias,
		C.int(flg),
		kcInData,
		C.int(inDataLength),
		(*C.uchar)(kcInSign),
		C.int(inputSignLength),
		(*C.char)(unsafe.Pointer(&kcOutData)),
		(*C.int)(unsafe.Pointer(&kcOutDataLen)),
		(*C.char)(unsafe.Pointer(&kcOutVerifyInfo)),
		(*C.int)(unsafe.Pointer(&kcOutVerifyInfoLen)),
		C.int(kcInCertID),
		(*C.char)(unsafe.Pointer(&kcOutCert)),
		(*C.int)(unsafe.Pointer(&kcOutCertLen)),
	))

	if rc != 0 {
		if val, ok := KcErrors[rc]; ok {
			return nil, fmt.Errorf("lib: VerifyData: verifyData error: %s", val)
		}
		return nil, fmt.Errorf("lib: VerifyData: verifyData error: %d", rc)
	}

	result := []string{}
	//result = append(result, C.GoString((*C.char)(kcOutData)))
	//result = append(result, C.GoString((*C.char)(kcOutVerifyInfo)))
	//result = append(result, C.GoString((*C.char)(kcOutCert)))
	result = append(result, string(kcOutData[:]))
	result = append(result, string(kcOutVerifyInfo[:]))
	result = append(result, string(kcOutCert[:]))
	return result, nil
}

//func byteSlice(content []byte) []byte {
//	for i, v := range content {
//		if v == 0 {
//			return content[:i]
//		}
//	}
//	return content
//}
