from FeatureVectorExtractor import FeatureVectorExtractor
import ModelTrainer

#prep data:
testSHA256 = '0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415'
sample = FeatureVectorExtractor(testSHA256,[])
sample.ExtractEntriesKeys()
print (sample.entry_keys)


def get_benign_sample


