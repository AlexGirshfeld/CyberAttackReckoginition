import pandas as pd
import numpy as np
from chefboost import Chefboost as chef
from output.FeatureVectorExtractor import FeatureVectorExtractor

class ModelTrainer:
    def __init__(self, apkList,features):
        self.SHA256List = apkList
        self.FeatureVector = features

    def createDataFrame(self, SHA256List, featureVectorParams):
        dataDicts = []
        for apk in SHA256List:
            try:
                fve = FeatureVectorExtractor(apk, featureVectorParams)
            except FileNotFoundError:
                continue
            featureVectorDict = fve.ExtractFeatureVector()
            featureVectorDict['Decision'] = fve.ExtractLabel()
            dataDicts.append(featureVectorDict)
        featureVectorsArray = np.array([list(vector.values()) for vector in dataDicts])
        returndf = pd.DataFrame(featureVectorsArray, columns = dataDicts[0].keys())
        return returndf

    def TrainDTree(self):
        df = self.createDataFrame(self.SHA256List, self.FeatureVector)
        config = {'algorithm': 'C4.5'}
        model = chef.fit(df,config)
        return model

    def TrainRandomForest(self):
        df = self.createDataFrame(self.SHA256List, self.FeatureVector)
        config = {'algorithm':'C4.5', 'enableRandomForest': True, 'num_of_trees': 5}
        randomForestModel = chef.fit(df, config)
        return randomForestModel






def test_CreateDataFrame():
    testSHA256List = ['0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415','0b0a3531cfa5f207b701e51656b8941241a9e8ed40dde4a5979e16e9cb6a8b0f']
    testFeatureVectorParams = {'APK file calls sensitive API methods', 'APK file removed the app icon', 'com.mopub.izdirLdedbezvC'}
    dataDicts = []
    for tSHA256 in testSHA256List:
        try:
            FeatureVectorExtractorMock = FeatureVectorExtractor(tSHA256, testFeatureVectorParams)
        except FileNotFoundError:
            continue
        featureVectorDict = FeatureVectorExtractorMock.ExtractFeatureVector()
        featureVectorDict['Decision'] = FeatureVectorExtractorMock.ExtractLabel()
        dataDicts.append(featureVectorDict)
    featureVectorsArray = np.array([list(vector.values()) for vector in dataDicts])
    manualdf = pd.DataFrame(featureVectorsArray, columns = dataDicts[0].keys())
    #print(manualdf.head())
    mockModelTrainer = ModelTrainer(testSHA256List, testFeatureVectorParams)
    testeddf = mockModelTrainer.createDataFrame(testSHA256List, testFeatureVectorParams)
    df2 = pd.DataFrame(np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]]),
                       columns=['a', 'b', 'c'])
    assert manualdf.equals(testeddf)
    assert not manualdf.equals(df2)


def test_TrainDtree():
    testSHA256List = ['0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415','0b0a3531cfa5f207b701e51656b8941241a9e8ed40dde4a5979e16e9cb6a8b0f', '0a0a5c4b8da52903ffb6918bd580992d347e8e402033114aba0f0f4840445fe6','0a0bc5c20a0aee996d8752798ada9f79fd5d5b34203601232ef07e6bee95c7b4']
    testFeatureVectorParams = {'APK file calls sensitive API methods', 'APK file removed the app icon', 'com.mopub.izdirLdedbezvC', 'APK file uses the Java Reflection API','APK file source code contains a hard-coded URL'}
    MockModelTrainer = ModelTrainer(testSHA256List, testFeatureVectorParams)

    #benign Sample
    MockFeatureVectorExtractor = FeatureVectorExtractor('0a0c866f26539611bbe28289e0582a95ffa405516c6ff857f36eabd09a7c34b4', testFeatureVectorParams)
    featureVectorTopredict = list(MockFeatureVectorExtractor.ExtractFeatureVector().values())
    testModel = MockModelTrainer.TrainDTree()
    prediction = chef.predict(testModel,featureVectorTopredict)
    assert prediction == 'no'

    #mlware sample
    MockFeatureVectorExtractor = FeatureVectorExtractor('0c0da0b5a528f90d6817ffdb2095a3a0721ceed919bac1cd3d32369825fef6d5', testFeatureVectorParams)
    featureVectorTopredict = list(MockFeatureVectorExtractor.ExtractFeatureVector().values())
    testModel = MockModelTrainer.TrainDTree()
    prediction = chef.predict(testModel,featureVectorTopredict)
    #assert prediction == 'yes'