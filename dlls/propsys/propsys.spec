  3 stub GetProxyDllInfo
400 stub @
402 stub @
403 stub @
404 stub @
405 stub @
406 stub @
407 stub @
408 stub @
409 stub @
410 stub @
411 stub @
412 stub @
413 stub @
414 stub @
415 stub @
416 stub @
417 stub @
418 stub @
420 stub @
421 stub @
422 stub @

@ stub ClearPropVariantArray
@ stub ClearVariantArray
@ stdcall -private DllCanUnloadNow()
@ stdcall -private DllGetClassObject(ptr ptr ptr)
@ stdcall -private DllRegisterServer()
@ stdcall -private DllUnregisterServer()
@ stub InitPropVariantFromBooleanVector
@ stdcall InitPropVariantFromBuffer(ptr long ptr)
@ stdcall InitPropVariantFromCLSID(ptr ptr)
@ stub InitPropVariantFromDoubleVector
@ stub InitPropVariantFromFileTime
@ stub InitPropVariantFromFileTimeVector
@ stdcall InitPropVariantFromGUIDAsString(ptr ptr)
@ stub InitPropVariantFromInt16Vector
@ stub InitPropVariantFromInt32Vector
@ stub InitPropVariantFromInt64Vector
@ stub InitPropVariantFromPropVariantVectorElem
@ stub InitPropVariantFromResource
@ stub InitPropVariantFromStrRet
@ stub InitPropVariantFromStringAsVector
@ stdcall InitPropVariantFromStringVector(ptr long ptr)
@ stub InitPropVariantFromUInt16Vector
@ stub InitPropVariantFromUInt32Vector
@ stub InitPropVariantFromUInt64Vector
@ stub InitPropVariantVectorFromPropVariant
@ stub InitVariantFromBooleanArray
@ stdcall InitVariantFromBuffer(ptr long ptr)
@ stub InitVariantFromDoubleArray
@ stdcall InitVariantFromFileTime(ptr ptr)
@ stub InitVariantFromFileTimeArray
@ stdcall InitVariantFromGUIDAsString(ptr ptr)
@ stub InitVariantFromInt16Array
@ stub InitVariantFromInt32Array
@ stub InitVariantFromInt64Array
@ stub InitVariantFromResource
@ stub InitVariantFromStrRet
@ stub InitVariantFromStringArray
@ stub InitVariantFromUInt16Array
@ stub InitVariantFromUInt32Array
@ stub InitVariantFromUInt64Array
@ stub InitVariantFromVariantArrayElem
@ stub PSCoerceToCanonicalValue
@ stub PSCreateAdapterFromPropertyStore
@ stub PSCreateDelayedMultiplexPropertyStore
@ stdcall PSCreateMemoryPropertyStore(ptr ptr)
@ stub PSCreateMultiplexPropertyStore
@ stub PSCreatePropertyChangeArray
@ stdcall PSCreatePropertyStoreFromObject(ptr long ptr ptr)
@ stub PSCreatePropertyStoreFromPropertySetStorage
@ stub PSCreateSimplePropertyChange
@ stub PSEnumeratePropertyDescriptions
@ stub PSFormatForDisplay
@ stub PSFormatForDisplayAlloc
@ stub PSFormatPropertyValue
@ stub PSGetItemPropertyHandler
@ stub PSGetItemPropertyHandlerWithCreateObject
@ stdcall PSGetNameFromPropertyKey(ptr ptr)
@ stub PSGetNamedPropertyFromPropertyStorage
@ stdcall PSGetPropertyDescription(ptr ptr ptr)
@ stub PSGetPropertyDescriptionByName
@ stdcall PSGetPropertyDescriptionListFromString(wstr ptr ptr)
@ stub PSGetPropertyFromPropertyStorage
@ stdcall PSGetPropertyKeyFromName(wstr ptr)
@ stdcall PSGetPropertySystem(ptr ptr)
@ stub PSGetPropertyValue
@ stub PSLookupPropertyHandlerCLSID
@ stdcall PSPropertyKeyFromString(wstr ptr)
@ stdcall PSRefreshPropertySchema()
@ stdcall PSRegisterPropertySchema(wstr)
@ stub PSSetPropertyValue
@ stdcall PSStringFromPropertyKey(ptr ptr long)
@ stdcall PSUnregisterPropertySchema(wstr)
@ stdcall PropVariantChangeType(ptr ptr long long)
@ stdcall PropVariantCompareEx(ptr ptr long long)
@ stub PropVariantGetBooleanElem
@ stub PropVariantGetDoubleElem
@ stub PropVariantGetElementCount
@ stub PropVariantGetFileTimeElem
@ stub PropVariantGetInt16Elem
@ stub PropVariantGetInt32Elem
@ stub PropVariantGetInt64Elem
@ stdcall PropVariantGetStringElem(ptr long ptr)
@ stub PropVariantGetUInt16Elem
@ stub PropVariantGetUInt32Elem
@ stub PropVariantGetUInt64Elem
@ stdcall PropVariantToBSTR(ptr ptr)
@ stdcall PropVariantToBoolean(ptr ptr)
@ stub PropVariantToBooleanVector
@ stub PropVariantToBooleanVectorAlloc
@ stub PropVariantToBooleanWithDefault
@ stdcall PropVariantToBuffer(ptr ptr long)
@ stdcall PropVariantToDouble(ptr ptr)
@ stub PropVariantToDoubleVector
@ stub PropVariantToDoubleVectorAlloc
@ stub PropVariantToDoubleWithDefault
@ stub PropVariantToFileTime
@ stub PropVariantToFileTimeVector
@ stub PropVariantToFileTimeVectorAlloc
@ stdcall PropVariantToGUID(ptr ptr)
@ stdcall PropVariantToInt16(ptr ptr)
@ stub PropVariantToInt16Vector
@ stub PropVariantToInt16VectorAlloc
@ stub PropVariantToInt16WithDefault
@ stdcall PropVariantToInt32(ptr ptr)
@ stub PropVariantToInt32Vector
@ stub PropVariantToInt32VectorAlloc
@ stub PropVariantToInt32WithDefault
@ stdcall PropVariantToInt64(ptr ptr)
@ stub PropVariantToInt64Vector
@ stub PropVariantToInt64VectorAlloc
@ stub PropVariantToInt64WithDefault
@ stub PropVariantToStrRet
@ stdcall PropVariantToString(ptr ptr long)
@ stdcall PropVariantToStringAlloc(ptr ptr)
@ stub PropVariantToStringVector
@ stub PropVariantToStringVectorAlloc
@ stdcall PropVariantToStringWithDefault(ptr wstr)
@ stdcall PropVariantToUInt16(ptr ptr)
@ stub PropVariantToUInt16Vector
@ stub PropVariantToUInt16VectorAlloc
@ stub PropVariantToUInt16WithDefault
@ stdcall PropVariantToUInt32(ptr ptr)
@ stub PropVariantToUInt32Vector
@ stub PropVariantToUInt32VectorAlloc
@ stdcall PropVariantToUInt32WithDefault(ptr long)
@ stdcall PropVariantToUInt64(ptr ptr)
@ stub PropVariantToUInt64Vector
@ stub PropVariantToUInt64VectorAlloc
@ stub PropVariantToUInt64WithDefault
@ stdcall PropVariantToVariant(ptr ptr)
@ stub StgDeserializePropVariant
@ stub StgSerializePropVariant
@ stub VariantCompare
@ stub VariantGetBooleanElem
@ stub VariantGetDoubleElem
@ stub VariantGetElementCount
@ stub VariantGetInt16Elem
@ stub VariantGetInt32Elem
@ stub VariantGetInt64Elem
@ stub VariantGetStringElem
@ stub VariantGetUInt16Elem
@ stub VariantGetUInt32Elem
@ stub VariantGetUInt64Elem
@ stub VariantToBoolean
@ stub VariantToBooleanArray
@ stub VariantToBooleanArrayAlloc
@ stub VariantToBooleanWithDefault
@ stub VariantToBuffer
@ stub VariantToDosDateTime
@ stub VariantToDouble
@ stub VariantToDoubleArray
@ stub VariantToDoubleArrayAlloc
@ stub VariantToDoubleWithDefault
@ stub VariantToFileTime
@ stdcall VariantToGUID(ptr ptr)
@ stub VariantToInt16
@ stub VariantToInt16Array
@ stub VariantToInt16ArrayAlloc
@ stub VariantToInt16WithDefault
@ stub VariantToInt32
@ stub VariantToInt32Array
@ stub VariantToInt32ArrayAlloc
@ stub VariantToInt32WithDefault
@ stub VariantToInt64
@ stub VariantToInt64Array
@ stub VariantToInt64ArrayAlloc
@ stub VariantToInt64WithDefault
@ stdcall VariantToPropVariant(ptr ptr)
@ stub VariantToStrRet
@ stdcall VariantToString(ptr ptr long)
@ stub VariantToStringAlloc
@ stub VariantToStringArray
@ stub VariantToStringArrayAlloc
@ stdcall VariantToStringWithDefault(ptr wstr)
@ stub VariantToUInt16
@ stub VariantToUInt16Array
@ stub VariantToUInt16ArrayAlloc
@ stub VariantToUInt16WithDefault
@ stub VariantToUInt32
@ stub VariantToUInt32Array
@ stub VariantToUInt32ArrayAlloc
@ stub VariantToUInt32WithDefault
@ stub VariantToUInt64
@ stub VariantToUInt64Array
@ stub VariantToUInt64ArrayAlloc
@ stub VariantToUInt64WithDefault
