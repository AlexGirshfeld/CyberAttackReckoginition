import os
import xml.etree.ElementTree as ET
import pytest



class FeatureVectorExtractor:
    def __init__(self, reportSHA256, FeatureVectorList):
        dynamicReportFilePath, staticReportFilePath = self.retriveReportFilePath(reportSHA256)
        self.staticTree = ET.parse(staticReportFilePath)
        self.dynamicTree = ET.parse(dynamicReportFilePath)
        self.featureVectorKeys = FeatureVectorList

    def ExtractLabel(self):
        sroot = self.staticTree.getroot()
        malwareTag = sroot.findall('./malware')
        return malwareTag[0].text

    def ExtractFeatureVector(self):
        featureVector = {}
        for key in self.featureVectorKeys:
            featureVector[key] = self.CheckFeatureInDynamicAndStaticReports(key)
        return featureVector


    def retriveReportFilePath(self, reportSHA256):
        #print('Checking the dir:'+f"malware/{reportSHA256[0:2]}/{reportSHA256[2:4]}/{reportSHA256}_sa", os.path.exists(f"malware/{reportSHA256[0:2]}/{reportSHA256[2:4]}/"), os.path.isfile())
        if os.path.isfile(f"malware/{reportSHA256[0:2]}/{reportSHA256[2:4]}/{reportSHA256}_sa.xml"):
            staticReportFilePath = f"malware/{reportSHA256[0:2]}/{reportSHA256[2:4]}/{reportSHA256}_sa.xml"
            dynamicReportFilePath = f"malware/{reportSHA256[0:2]}/{reportSHA256[2:4]}/{reportSHA256}_da.xml"
        else:
            staticReportFilePath = f"benign/{reportSHA256[0:2]}/{reportSHA256[2:4]}/{reportSHA256}_sa.xml"
            dynamicReportFilePath = f"benign/{reportSHA256[0:2]}/{reportSHA256[2:4]}/{reportSHA256}_da.xml"
        return dynamicReportFilePath, staticReportFilePath

    def CheckFeatureInDynamicAndStaticReports(self, fullEntryText):
        feature = False
        feature = feature or self.checkFeatureInStaticReport(fullEntryText)
        feature = feature or self.checkFeatureInDynamicReport(fullEntryText)
        return feature

    def checkFeatureInDynamicReport(self, EntryText):
        feature = False
        feature = feature or self.checkEntryInTree(EntryText, self.dynamicTree.getroot())
        return feature

    def checkFeatureInStaticReport(self, EntryText):
        return self.checkEntryInTree(EntryText, self.staticTree.getroot())

    def checkEntryInTree(self, EntryText, root):
        entries = root.findall(".//entry")
        stringList = self.convertEntriesToStringList(entries)
        return EntryText in stringList

    def convertEntriesToStringList(self, entries):
        stringList = []
        for e in entries:
            stringList.append(e.text)
        return stringList

def test_ExtractLabel():
    testSHA256 = '0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415'
    FeatureVectorExtractorMock = FeatureVectorExtractor(testSHA256,[])
    assert FeatureVectorExtractorMock.ExtractLabel() == 'yes'
    testSHA256 = '0c0b5e0f7808b76b040ea433ca64dda1c4f635749b2ef61a21e41b6f96325512'
    FeatureVectorExtractorMock = FeatureVectorExtractor(testSHA256,[])
    assert FeatureVectorExtractorMock.ExtractLabel() == 'no'


def test_ExtractFeatureVector():
    testSHA256 = '0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415'
    testCaseVector = {'APK file communicates over a network socket': True, 'android.net.wifi.WIFI_STATE_CHANGED': True,
     'android.permission.WRITE_EXTERNAL_STORAGE': True, 'android/net/ConnectivityManager;->getActiveNetworkInfo': True,
     'abcdefg': False, 'APK file has the ability to install other APK files': True}
    FeatureVectorExtractorMock = FeatureVectorExtractor(testSHA256, testCaseVector)
    extractedVector = FeatureVectorExtractorMock.ExtractFeatureVector()
    for feature in testCaseVector.keys():
        assert testCaseVector[feature] == extractedVector[feature]


def test_checkEntryInTree():
    testSHA256 = '0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415'
    testCases = {'APK file communicates over a network socket': True, 'android.net.wifi.WIFI_STATE_CHANGED':True, 'android.permission.WRITE_EXTERNAL_STORAGE':True,'android/net/ConnectivityManager;->getActiveNetworkInfo':True, 'abcdefg':False, 'APK file has the ability to install other APK files':True}
    FeatureVectorExtractorMock = FeatureVectorExtractor(testSHA256 , testCases.keys())
    root = FeatureVectorExtractorMock.staticTree.getroot()
    for case in testCases.keys():
        assert FeatureVectorExtractorMock.checkEntryInTree(case,root) == testCases[case]

def test_checkFeatureInStaticReport():
    testSHA256 = '0b0a3531cfa5f207b701e51656b8941241a9e8ed40dde4a5979e16e9cb6a8b0f'
    testCases = {'com.mopub.IjIcspYolQ': True, 'abcdefg':False, 'APK file has the ability to install other APK files':True, "android.intent.action.MAIN": True,"gandroid.intent.action.MAIN":False }
    FeatureVectorExtractorMock = FeatureVectorExtractor(testSHA256, testCases.keys())
    for case in testCases.keys():
        assert FeatureVectorExtractorMock.checkFeatureInStaticReport(case) == testCases[case]

def test_CheckFeatureInDynamicAndStaticReports():
    testSHA256 = '0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415'
    testCases = {'APK file communicates over a network socket': True, 'android.net.wifi.WIFI_STATE_CHANGED': True,
                 'android.permission.WRITE_EXTERNAL_STORAGE': True,
                 'android/net/ConnectivityManager;->getActiveNetworkInfo': True, 'abcdefg': False,
                 'APK file has the ability to install other APK files': True}
    FeatureVectorExtractorMock = FeatureVectorExtractor(testSHA256, testCases.keys())
    for case in testCases.keys():
        assert FeatureVectorExtractorMock.CheckFeatureInDynamicAndStaticReports(case) == testCases[case]



