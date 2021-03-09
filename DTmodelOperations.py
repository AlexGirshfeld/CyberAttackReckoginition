import numpy as np
import pandas as pd
import datetime
np.random.seed(1337)  # for reproducibility
from sklearn.datasets import load_digits
from sklearn.model_selection import train_test_split
from sklearn.metrics.classification import accuracy_score
from FeatureVectorExtractor import FeatureVectorExtractor
from FeatureVectorExtractor import findRandomAPK
from ModelTrainer import ModelTrainer
import chefboost as chef

data =  pd.read_csv(r'dfAfterCorr.csv')
featureVector = list(data.columns)
apkHashes = pd.read_csv('hashes.csv').values.tolist()
apkHashesList =[]
for a in apkHashes:
    apkHashesList.append(a[0])
ourModel= ModelTrainer(apkHashesList, featureVector)
# Loading dataset


dtClassifier = ourModel.TrainDTree()

print("pause")
# Splitting data

chef.save_model(dtClassifier, "DTmodel.pkl")
#validation with the original data:
def run_validation_on_external_data(numOfapks, classifier):
    featureVector = list(data.columns)
    correct = 0
    numOfapkschecked = numOfapks
    falsePositive =0
    falsseNegative = 0
    wrongApks = []
    mapDict = {'yes':1, 'no': 0}
    for i in range(numOfapks):
        apkHash = findRandomAPK()
        try:
            fve = FeatureVectorExtractor(apkHash, featureVector)
            label = fve.ExtractLabel()
            if label == 'n/a':
                numOfapkschecked = numOfapkschecked -1
                continue
            fv = fve.ExtractFeatureVector()
        except Exception as e:
            numOfapkschecked = numOfapkschecked-1
            continue
        prediction = chef.predict(dtClassifier, fv)
        if prediction == label:
            correct = correct + 1
        else:
            wrongApks.append(apkHash)
            if mapDict[label] == 1:
                falsseNegative= falsseNegative +1
            if mapDict[label] == 0:
                falsePositive = falsePositive +1
    pd.DataFrame(wrongApks).to_csv('mishitsApsDT.csv', index=False)
    print(f"Accuracy is {correct/numOfapkschecked}")
    print(f"FP rate is {falsePositive/numOfapkschecked}")
    print(f"misditect rte is {falsseNegative/numOfapkschecked}")

run_validation_on_external_data(1000, dtClassifier)


