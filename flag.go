package mkc

// Константы, определяющие способ хранения ключей/сертификатов (вид хранилища носителя)
const (
	KCST_PKCS12     = 1   // Файловая система (небезопасный способ хранения ключей)
	KCST_KZIDCARD   = 2   // Удостоверение личности гражданина РК
	KCST_KAZTOKEN   = 4   // Казтокен
	KCST_ETOKEN72K  = 8   // eToken 72k
	KCST_JACARTA    = 16  // JaCarta
	KCST_X509CERT   = 32  // Сертификат X509
	KCST_AKEY       = 64  // aKey
	KCST_ETOKEN5110 = 128 // eToken 5110
)

// Константы, определяющие принадлежность сертификата.
const (
	KC_CERT_CA           = 513 // Корневой сертификат УЦ
	KC_CERT_INTERMEDIATE = 514 // Сертификат промежуточного УЦ
	KC_CERT_USER         = 516 // Сертификат пользователя
)

// Константы, определяющие тип кодировки.
const (
	KC_CERT_DER = 257 // Кодировка DER
	KC_CERT_PEM = 259 // Кодировка PEM
	KC_CERT_B64 = 260 // Кодировка Base64
)

// Константы, определяющие тип валидации.
const (
	KC_USE_NOTHING = 1025 // Не делать проверок
	KC_USE_CRL     = 1026 // Проверка сертификата по списку отозванных сертификатов
	KC_USE_OCSP    = 1028 // Проверка сертификата посредством сервиса OCSP
)

// Константы, определяющие алгоритм хеширования.
const (
	KC_HASH_SHA256     = 131072
	KC_HASH_GOST95     = 262144
	KC_HASH_GOST15_256 = 1048576
	KC_HASH_GOST15_512 = 2097152
)

// Константы, определяющие значение поля/расширения в запросе/сертификате.
const (
	KC_CERTPROP_ISSUER_COUNTRYNAME   = 2049 // Страна издателя
	KC_CERTPROP_ISSUER_SOPN          = 2050 // Название штата или провинции издателя
	KC_CERTPROP_ISSUER_LOCALITYNAME  = 2051 // Населённый пункт издателя
	KC_CERTPROP_ISSUER_ORG_NAME      = 2052 // Наименование организации издателя
	KC_CERTPROP_ISSUER_ORGUNIT_NAME  = 2053 // Название организационного подразделения издателя
	KC_CERTPROP_ISSUER_COMMONNAME    = 2054 // Имя Фамилия издателя
	KC_CERTPROP_SUBJECT_COUNTRYNAME  = 2055 // Страна субъекта
	KC_CERTPROP_SUBJECT_SOPN         = 2056 // Название штата или провинции субъекта
	KC_CERTPROP_SUBJECT_LOCALITYNAME = 2057 // Населенный пункт субъекта
	KC_CERTPROP_SUBJECT_COMMONNAME   = 2058 // Общее имя субъекта
	KC_CERTPROP_SUBJECT_GIVENNAME    = 2059 // Имя субъекта
	KC_CERTPROP_SUBJECT_SURNAME      = 2060 // Фамилия субъекта
	KC_CERTPROP_SUBJECT_SERIALNUMBER = 2061 // Серийный номер субъекта
	KC_CERTPROP_SUBJECT_EMAIL        = 2062 // e-mail субъекта
	KC_CERTPROP_SUBJECT_ORG_NAME     = 2063 // Наименование организации субъекта
	KC_CERTPROP_SUBJECT_ORGUNIT_NAME = 2064 // Название организационного подразделения субъекта
	KC_CERTPROP_SUBJECT_BC           = 2065 // Бизнес категория субъекта
	KC_CERTPROP_SUBJECT_DC           = 2066 // Доменный компонент субъекта
	KC_CERTPROP_NOTBEFORE            = 2067 // Дата действителен с
	KC_CERTPROP_NOTAFTER             = 2068 // Дата действителен по
	KC_CERTPROP_KEY_USAGE            = 2069 // Использование ключа
	KC_CERTPROP_EXT_KEY_USAGE        = 2070 // Расширенное использование ключа
	KC_CERTPROP_AUTH_KEY_ID          = 2071 // Идентификатор ключа центра сертификации
	KC_CERTPROP_SUBJ_KEY_ID          = 2072 // Идентификатор ключа субъекта
	KC_CERTPROP_CERT_SN              = 2073 // Серийный номер сертификата
	KC_CERTPROP_ISSUER_DN            = 2074 // Отличительное имя издателя
	KC_CERTPROP_SUBJECT_DN           = 2075 // Отличительное имя субъекта
	KC_CERTPROP_SIGNATURE_ALG        = 2076 // Алгоритм подписи
	KC_CERTPROP_PUBKEY               = 2077 // Получение открытого ключа
	KC_CERTPROP_POLICIES_ID          = 2078 // Получение идентификатора политики сертификата
	KC_CERTPROP_OCSP                 = 2079 // Получение URL-адреса OCSP
	KC_CERTPROP_GET_CRL              = 2080 // Получение URL-адреса CRL
	KC_CERTPROP_GET_DELTA_CRL        = 2081 // Получение URL-адреса delta CRL
)

var CertPropMap = map[int]string{
	2049: "ISSUER_COUNTRYNAME",
	2050: "ISSUER_SOPN",
	2051: "ISSUER_LOCALITYNAME",
	2052: "ISSUER_ORG_NAME",
	2053: "ISSUER_ORGUNIT_NAME",
	2054: "ISSUER_COMMONNAME",
	2055: "SUBJECT_COUNTRYNAME",
	2056: "SUBJECT_SOPN",
	2057: "SUBJECT_LOCALITYNAME",
	2058: "SUBJECT_COMMONNAME",
	2059: "SUBJECT_GIVENNAME",
	2060: "SUBJECT_SURNAME",
	2061: "SUBJECT_SERIALNUMBER",
	2062: "SUBJECT_EMAIL",
	2063: "SUBJECT_ORG_NAME",
	2064: "SUBJECT_ORGUNIT_NAME",
	2065: "SUBJECT_BC",
	2066: "SUBJECT_DC",
	2067: "NOTBEFORE",
	2068: "NOTAFTER",
	2069: "KEY_USAGE",
	2070: "EXT_KEY_USAGE",
	2071: "AUTH_KEY_ID",
	2072: "SUBJ_KEY_ID",
	2073: "CERT_SN",
	2074: "ISSUER_DN",
	2075: "SUBJECT_DN",
	2076: "SIGNATURE_ALG",
	2077: "PUBKEY",
	2078: "POLICIES_ID",
	2079: "OCSP",
	2080: "GET_CRL",
	2081: "GET_DELTA_CRL",
}

// Константы, определяющие дополнительные условия выполнения операций. Используется как параметр в функциях.
const (
	KC_SIGN_DRAFT        = 1      // Сырая подпись (draft sign)
	KC_SIGN_CMS          = 2      // Подпись в формате CMS
	KC_IN_PEM            = 4      // Входные данные в формате PEM
	KC_IN_DER            = 8      // Входные данные в кодировке DER
	KC_IN_BASE64         = 16     // Входные данные в кодировке BASE64
	KC_IN2_BASE64        = 32     // Дополнительные входные данные в кодировке BASE64
	KC_DETACHED_DATA     = 64     // Отсоединенная подпись
	KC_WITH_CERT         = 128    // Вложить сертификат в подпись
	KC_WITH_TIMESTAMP    = 256    // Добавить в подпись метку времени
	KC_OUT_PEM           = 512    // Выходные данные в формате PEM
	KC_OUT_DER           = 1024   // Выходные данные в кодировке DER
	KC_OUT_BASE64        = 2048   // Выходные данные в кодировке BASE64
	KC_PROXY_OFF         = 4096   // Отключить использование прокси-сервера и стереть настройки.
	KC_PROXY_ON          = 8192   // Включить и установить настройки прокси-сервера (адрес и порт)
	KC_PROXY_AUTH        = 16384  // Прокси-сервер требует авторизацию (логин/пароль)
	KC_IN_FILE           = 32768  // Использовать, если параметр inData/outData содержит абсолютный путь к файлу.
	KC_NOCHECKCERTTIME   = 65536  // Не проверять срок действия сертификата при построении цепочки до корневого (для проверки старых подписей с просроченным сертификатом)
	KC_GET_OCSP_RESPONSE = 524288 // Получить ответ от OCSP-сервиса =
)

// Константы, определяющие подробные коды ошибок времени выполнения. Код ошибки и подробный текст можно получить с помощью функции GetLastError.
const (
	KCR_OK                              = 0         // Нет ошибки
	KCR_ERROR_READ_PKCS12               = 149946370 // 149946370Невозможно прочитать файл формата pkcs#12
	KCR_ERROR_OPEN_PKCS12               = 149946371 // Невозможно открыть файл формата pkcs12
	KCR_INVALID_PROPID                  = 149946372 // Недопустимый идентификатор расширения сертификата
	KCR_BUFFER_TOO_SMALL                = 149946373 // Размер буфера слишком мал
	KCR_CERT_PARSE_ERROR                = 149946374 // Невозможно разобрать ( распарсить ) сертификат
	KCR_INVALID_FLAG                    = 149946375 // Недопустимый флаг
	KCR_OPENFILEERR                     = 149946376 // Невозможно открыть файл
	KCR_INVALIDPASSWORD                 = 149946377 // Неправильный пароль
	KCR_MEMORY_ERROR                    = 149946381 // Невозможно выделить память
	KCR_CHECKCHAINERROR                 = 149946382 // Не найден сертификат УЦ или сертификат пользователя при проверки цепочки
	KCR_VALIDTYPEERROR                  = 149946384 // Недопустимый тип валидации сертификата
	KCR_BADCRLFORMAT                    = 149946385 // Некорректный формат CRL
	KCR_LOADCRLERROR                    = 149946386 // Невозможно загрузить CRL
	KCR_LOADCRLSERROR                   = 149946387 // Невозможно загрузить CRL-ы
	KCR_UNKNOWN_ALG                     = 149946389 // Неизвестный алгоритм подписи
	KCR_KEYNOTFOUND                     = 149946390 // Не найден приватный ключ пользователя
	KCR_SIGN_INIT_ERROR                 = 149946391 // Невозможно инициализировать менеджера подписи
	KCR_SIGN_ERROR                      = 149946392 // Не удалось сгенерировать цифровую подпись
	KCR_ENCODE_ERROR                    = 149946393 // Ошибка шифрования
	KCR_INVALID_FLAGS                   = 149946394 // Недопустимые флаги
	KCR_CERTNOTFOUND                    = 149946395 // Не найден сертификат пользователя
	KCR_VERIFYSIGNERROR                 = 149946396 // Ошибка верификации подписи xml
	KCR_BASE64_DECODE_ERROR             = 149946397 // Ошибка дешифровки из Base 64
	KCR_UNKNOWN_CMS_FORMAT              = 149946398 // Неизвестный формат CMS
	KCR_CA_CERT_NOT_FOUND               = 149946400 // Не найден сертификат УЦ
	KCR_XMLSECINIT_ERROR                = 149946401 // Ошибка инициализации xmlsec
	KCR_LOADTRUSTEDCERTSERR             = 149946402 // Ошибка загрузки доверенных сертификатов
	KCR_SIGN_INVALID                    = 149946403 // Недопустимая подпись xml
	KCR_NOSIGNFOUND                     = 149946404 // Не найдена подпись во входных данных
	KCR_DECODE_ERROR                    = 149946405 // Ошибка дешифрования
	KCR_XMLPARSEERROR                   = 149946406 // Невозможно разобрать (распарсить) xml
	KCR_XMLADDIDERROR                   = 149946407 // Не удалось добавить атрибут ID
	KCR_XMLINTERNALERROR                = 149946408 // Ошибка при работе с xml
	KCR_XMLSETSIGNERROR                 = 149946409 // Не удалось подписать xml
	KCR_OPENSSLERROR                    = 149946410 // Ошибка openssl
	KCR_NOTOKENFOUND                    = 149946412 // Не найден токен
	KCR_OCSP_ADDCERTERR                 = 149946413 // Не удалось добавить сертификат в ocsp
	KCR_OCSP_PARSEURLERR                = 149946414 // Не удалось разобрать url
	KCR_OCSP_ADDHOSTERR                 = 149946415 // Не удалось добавить хост
	KCR_OCSP_REQERR                     = 149946416 // Не удалось добавить текущее время в запрос
	KCR_OCSP_CONNECTIONERR              = 149946417 // Ошибка подключения к OCSP респондеру
	KCR_VERIFY_NODATA                   = 149946418 // Нет входных данных для верификации
	KCR_IDATTR_NOTFOUND                 = 149946419 // Не найден атрибут ID
	KCR_IDRANGE                         = 149946420 // Некорректный идентификатор
	KCR_READERNOTFOUND                  = 149946423 // Не найден ридер
	KCR_GETCERTPROPERR                  = 149946424 // Не удалось получить значение атрибута
	KCR_SIGNFORMMAT                     = 149946425 // Неизвестный формат подписи
	KCR_INDATAFORMAT                    = 149946426 // Неизвестный формат входных данных
	KCR_OUTDATAFORMAT                   = 149946427 // Неизвестный формат выходных данных
	KCR_VERIFY_INIT_ERROR               = 149946428 // Невозможно инициализировать менеджера верификации подписи
	KCR_VERIFY_ERROR                    = 149946429 // Не удалось верифицировать цифровую подпись
	KCR_HASH_ERROR                      = 149946430 // Не удалось хэшировать данные
	KCR_SIGNHASH_ERROR                  = 149946431 // Не удалось подписать хэшированные данные
	KCR_CACERTNOTFOUND                  = 149946432 // Не найден сертификат УЦ в хранилище сертификатов
	KCR_CERTTIMEINVALID                 = 149946434 // Срок действия сертификата истек либо еще не наступил
	KCR_CONVERTERROR                    = 149946435 // Ошибка записи сертификата в структуру X509
	KCR_TSACREATEQUERY                  = 149946436 // Ошибка генерации запроса timestamp
	KCR_CREATEOBJ                       = 149946437 // Ошибка записи OID в ASN1 структуру
	KCR_CREATENONCE                     = 149946438 // Ошибка генерации уникального числа
	KCR_HTTPERROR                       = 149946439 // Ошибка протокола http
	KCR_CADESBES_FAILED                 = 149946440 // Ошибка проверки расширения CADESBES в CMS
	KCR_CADEST_FAILED                   = 149946441 // Ошибка проверки подписи токена TSA
	KCR_NOTSATOKEN                      = 149946442 // В подписи не присутствует метка TSA
	KCR_INVALID_DIGEST_LEN              = 149946443 // Неправильная длина хэша
	KCR_GENRANDERROR                    = 149946444 // Ошибка генерации случайного числа
	KCR_SOAPNSERROR                     = 149946445 // Не найдены заголовки SOAP-сообщений
	KCR_GETPUBKEY                       = 149946446 // Ошибка экспорта публичного ключа
	KCR_GETCERTINFO                     = 149946447 // Ошибка получения информации о сертификате
	KCR_FILEREADERROR                   = 149946448 // Ошибка чтения файла
	KCR_CHECKERROR                      = 149946449 // Хэш не совпадает
	KCR_ZIPEXTRACTERR                   = 149946450 // Невозможно открыть архив
	KCR_NOMANIFESTFILE                  = 149946451 // Не найден MANIFEST
	KCR_VERIFY_TS_HASH                  = 149946452 // не удалось проверить Хэш подписи TS
	KCR_XADEST_FAILED                   = 149946453 // XAdES-T: Ошибка проверки подписи
	KCR_OCSP_RESP_STAT_MALFORMEDREQUEST = 149946454 // Неправильный запрос
	KCR_OCSP_RESP_STAT_INTERNALERROR    = 149946455 // Внутренняя ошибка
	KCR_OCSP_RESP_STAT_TRYLATER         = 149946456 // Попробуйте позже
	KCR_OCSP_RESP_STAT_SIGREQUIRED      = 149946457 // Должны подписать запрос
	KCR_OCSP_RESP_STAT_UNAUTHORIZED     = 149946458 // Запрос не авторизован
	KCR_VERIFY_ISSUERSERIALV2           = 149946459 // не удалось проверить IssuerSerialV2 в XAdES
	KCR_OCSP_CHECKCERTFROMRESP          = 149946460 // Ошибка проверки сертификата OCSP-респондера
	KCR_CRLEXPIRED                      = 149946461 // CRL-файл просрочен
	KCR_LIBRARYNOTINITIALIZED           = 149946625 // Библиотека не инициализирована
	KCR_ENGINELOADERR                   = 149946880 // Ошибка подключения (загрузки) модуля (engine)
	KCR_PARAM_ERROR                     = 149947136 // Некорректные входные данные
	KCR_CERT_STATUS_OK                  = 149947392 // Статус сертификата – валидный.(не является ошибкой, делается запись в лог)
	KCR_CERT_STATUS_REVOKED             = 149947393 // Статус сертификата – отозван.
	KCR_CERT_STATUS_UNKNOWN             = 149947394 // Статус сертификата – неизвестен.Например, не удалось установить издателя сертификата.=
)

var KcErrors = map[int]string{
	0:         "KCR_OK",
	149946370: "KCR_ERROR_READ_PKCS12",
	149946371: "KCR_ERROR_OPEN_PKCS12",
	149946372: "KCR_INVALID_PROPID",
	149946373: "KCR_BUFFER_TOO_SMALL",
	149946374: "KCR_CERT_PARSE_ERROR",
	149946375: "KCR_INVALID_FLAG",
	149946376: "KCR_OPENFILEERR",
	149946377: "KCR_INVALIDPASSWORD",
	149946381: "KCR_MEMORY_ERROR",
	149946382: "KCR_CHECKCHAINERROR",
	149946384: "KCR_VALIDTYPEERROR",
	149946385: "KCR_BADCRLFORMAT",
	149946386: "KCR_LOADCRLERROR",
	149946387: "KCR_LOADCRLSERROR",
	149946389: "KCR_UNKNOWN_ALG",
	149946390: "KCR_KEYNOTFOUND",
	149946391: "KCR_SIGN_INIT_ERROR",
	149946392: "KCR_SIGN_ERROR",
	149946393: "KCR_ENCODE_ERROR",
	149946394: "KCR_INVALID_FLAGS",
	149946395: "KCR_CERTNOTFOUND",
	149946396: "KCR_VERIFYSIGNERROR",
	149946397: "KCR_BASE64_DECODE_ERROR",
	149946398: "KCR_UNKNOWN_CMS_FORMAT",
	149946400: "KCR_CA_CERT_NOT_FOUND",
	149946401: "KCR_XMLSECINIT_ERROR",
	149946402: "KCR_LOADTRUSTEDCERTSERR",
	149946403: "KCR_SIGN_INVALID",
	149946404: "KCR_NOSIGNFOUND",
	149946405: "KCR_DECODE_ERROR",
	149946406: "KCR_XMLPARSEERROR",
	149946407: "KCR_XMLADDIDERROR",
	149946408: "KCR_XMLINTERNALERROR",
	149946409: "KCR_XMLSETSIGNERROR",
	149946410: "KCR_OPENSSLERROR",
	149946412: "KCR_NOTOKENFOUND",
	149946413: "KCR_OCSP_ADDCERTERR",
	149946414: "KCR_OCSP_PARSEURLERR",
	149946415: "KCR_OCSP_ADDHOSTERR",
	149946416: "KCR_OCSP_REQERR",
	149946417: "KCR_OCSP_CONNECTIONERR",
	149946418: "KCR_VERIFY_NODATA",
	149946419: "KCR_IDATTR_NOTFOUND",
	149946420: "KCR_IDRANGE",
	149946423: "KCR_READERNOTFOUND",
	149946424: "KCR_GETCERTPROPERR",
	149946425: "KCR_SIGNFORMMAT",
	149946426: "KCR_INDATAFORMAT",
	149946427: "KCR_OUTDATAFORMAT",
	149946428: "KCR_VERIFY_INIT_ERROR",
	149946429: "KCR_VERIFY_ERROR",
	149946430: "KCR_HASH_ERROR",
	149946431: "KCR_SIGNHASH_ERROR",
	149946432: "KCR_CACERTNOTFOUND",
	149946434: "KCR_CERTTIMEINVALID",
	149946435: "KCR_CONVERTERROR",
	149946436: "KCR_TSACREATEQUERY",
	149946437: "KCR_CREATEOBJ",
	149946438: "KCR_CREATENONCE",
	149946439: "KCR_HTTPERROR",
	149946440: "KCR_CADESBES_FAILED",
	149946441: "KCR_CADEST_FAILED",
	149946442: "KCR_NOTSATOKEN",
	149946443: "KCR_INVALID_DIGEST_LEN",
	149946444: "KCR_GENRANDERROR",
	149946445: "KCR_SOAPNSERROR",
	149946446: "KCR_GETPUBKEY",
	149946447: "KCR_GETCERTINFO",
	149946448: "KCR_FILEREADERROR",
	149946449: "KCR_CHECKERROR",
	149946450: "KCR_ZIPEXTRACTERR",
	149946451: "KCR_NOMANIFESTFILE",
	149946452: "KCR_VERIFY_TS_HASH",
	149946453: "KCR_XADEST_FAILED",
	149946454: "KCR_OCSP_RESP_STAT_MALFORMEDREQUEST",
	149946455: "KCR_OCSP_RESP_STAT_INTERNALERROR",
	149946456: "KCR_OCSP_RESP_STAT_TRYLATER",
	149946457: "KCR_OCSP_RESP_STAT_SIGREQUIRED",
	149946458: "KCR_OCSP_RESP_STAT_UNAUTHORIZED",
	149946459: "KCR_VERIFY_ISSUERSERIALV2",
	149946460: "KCR_OCSP_CHECKCERTFROMRESP",
	149946461: "KCR_CRLEXPIRED",
	149946625: "KCR_LIBRARYNOTINITIALIZED",
	149946880: "KCR_ENGINELOADERR",
	149947136: "KCR_PARAM_ERROR",
	149947392: "KCR_CERT_STATUS_OK",
	149947393: "KCR_CERT_STATUS_REVOKED",
	149947394: "KCR_CERT_STATUS_UNKNOWN",
}
