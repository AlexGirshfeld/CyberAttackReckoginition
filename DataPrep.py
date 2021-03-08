import os
import numpy as np
import ConfigFile
from FeatureVectorExtractor import FeatureVectorExtractor
import ModelTrainer

#prep data:
#testSHA256 = '0000eaf36c9d3217bfe5b89e027f86fd2de80bf541df1cabb337149ebdf5f415'
#sample = FeatureVectorExtractor(testSHA256,[])
#sample.ExtractEntriesKeys()
#print (sample.entry_keys)



def get_samples_hash(sample_dir, type):
    full_path = sample_dir + "\\" + type
    if os.path.isdir(full_path):
        files = []

        # r=root, d=directories, f = files
        for r, d, f in os.walk(full_path):
            for file in f:
                files.append(file[0:-7]) #remove _da.xml or _sa.xml
        unique_files = list(dict.fromkeys(files))
        return unique_files

def create_feature_vector_extractor_list(file_hashes, start, end):
    sliced_hashes = file_hashes[start:end]
    fve_list = []
    for hash in sliced_hashes:
        try:
            fve  = FeatureVectorExtractor(hash,[])
            fve.ExtractEntriesKeys()
        except:
            print("enter {hash} into blacklist")
        fve_list.append(fve)
    return fve_list

#create feature vector extractor list from file samples
path = r"C:\Users\nofar\Documents\לימודים\תואר 2\זיהוי התקפות סייבר\פרוייקט גמר"
benign_hashes = get_samples_hash(path,"benign")
benign_fve_list = create_feature_vector_extractor_list(benign_hashes,0,1000)

malware_hashes = get_samples_hash(path,"malware")
malware_fve_list = create_feature_vector_extractor_list(benign_hashes,0,1000)
print(5)












