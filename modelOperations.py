import numpy as np
import pandas as pd
import datetime
np.random.seed(1337)  # for reproducibility
from sklearn.datasets import load_digits
from sklearn.model_selection import train_test_split
from sklearn.metrics.classification import accuracy_score
from FeatureVectorExtractor import FeatureVectorExtractor
from FeatureVectorExtractor import findRandomAPK
from dbn import SupervisedDBNClassification


# Loading dataset
data =  pd.read_csv(r'dfwithoutNA.csv')
print(f"nan values:{data.isnull().sum().sum()}")
data = 1*data
data.dropna(inplace=True)
print(f"nan values:{data.isnull().sum().sum()}")
dataWithoutLabels = data.iloc[:,:-1]
labels = data.iloc[:,-1:]

labels = labels.Decision.map(dict(yes=1, no=0))
X, Y = dataWithoutLabels.to_numpy(), labels.to_numpy()


#digits = load_digits()
#X, Y = digits.data, digits.target


# Splitting data
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.8, random_state=0)


# Training
#classifier = SupervisedDBNClassification(hidden_layers_structure=[256, 256],learning_rate_rbm=0.05,learning_rate=0.1,n_epochs_rbm=10,n_iter_backprop=100,batch_size=32,activation_function='relu',dropout_p=0.2)
#classifier.fit(X_train, Y_train)

#classifier.save('DBNmodel.pkl')
classifier = SupervisedDBNClassification.load('DBNmodel.pkl')
# Test
Y_pred = classifier.predict(X_test)

print('Done.\nAccuracy: %f' % accuracy_score(Y_test, Y_pred))




#validation with the original data:
def run_validation_on_external_data(numOfapks, classifier):
    featureVector = list(data.columns)
    correct = 0
    numOfapkschecked = numOfapks
    falsePositive =0
    falsseNegative = 0
    mapDict = {'yes':1, 'no': 0}
    for i in range(numOfapks):
        apkHash = findRandomAPK()
        try:
            fve = FeatureVectorExtractor(apkHash, featureVector)
            label = fve.ExtractLabel()
            if label == 'n/a':
                numOfapkschecked = numOfapkschecked -1
                continue
            fv = fve.ExtractBinFeatureVector()
            fvArray = np.array(list(fv.values()),dtype='float64')
            fvArray = fvArray[:-1]
        except Exception as e:
            numOfapkschecked = numOfapkschecked-1
            continue
        prediction =  classifier.predict(fvArray)
        if prediction[0] == mapDict[label]:
            correct = correct + 1
        else:
            if mapDict[label] == 1:
                falsseNegative= falsseNegative +1
            if mapDict[label] == 0:
                falsePositive = falsePositive +1
    print(f"Accuracy is {correct/numOfapkschecked}")
    print(f"FP rate is {falsePositive/numOfapkschecked}")
    print(f"misditect rte is {falsseNegative/numOfapkschecked}")

run_validation_on_external_data(1000, classifier)