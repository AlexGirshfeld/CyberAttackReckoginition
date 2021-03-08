import os
from FeatureVectorExtractor import FeatureVectorExtractor
import pandas as pd

def get_samples_hash(sample_dir, type, start, end):
    full_path = sample_dir + "\\" + type
    if os.path.isdir(full_path):
        files = []
        # r=root, d=directories, f = files
        for r, d, f in os.walk(full_path):
            for file in f:
                files.append(file[0:-7]) #remove _da.xml or _sa.xml
        unique_files = list(dict.fromkeys(files))
        sliced_hashes = unique_files[start:end]
        return sliced_hashes

def create_feature_vector_extractor_list(file_hashes):
    fve_list = []
    count_bl = 0
    for hash in file_hashes:
        try:
            fve  = FeatureVectorExtractor(hash,[])
            fve.ExtractEntriesKeys()
            fve_list.append(fve) #add featureVectorExtractor object to list
        except:
            print(f"enter {hash} into blacklist")
            count_bl = count_bl + 1
    print(f"corrupted hash files number is  = {count_bl}")
    return fve_list

def generate_fves_hashes(start, end):
    #create feature vector extractor list from file samples and sliced hash list
    dir_path = os.path.dirname(os.path.realpath(__file__))
    os.chdir(dir_path)
    benign_hashes = get_samples_hash(dir_path,"benign", start, end)
    benign_fve_list = create_feature_vector_extractor_list(benign_hashes)

    malware_hashes = get_samples_hash(dir_path,"malware", start, end)
    malware_fve_list = create_feature_vector_extractor_list(malware_hashes)

    #combine benign and malware
    fve_list = benign_fve_list
    hash_list = benign_hashes
    hash_list.extend(malware_hashes)
    fve_list.extend(malware_fve_list)
    return fve_list, hash_list


fveList, hashList = generate_fves_hashes(0,1000)
allFeatures = []
for fve in fveList:
    allFeatures.extend(fve.entry_keys)

#save to csv files:
print("save data to csv files")
hash_dict = {'hash': hashList}
df = pd.DataFrame(hash_dict)
df.to_csv('hashes.csv', index=False)

feature_dict = {'feature' : allFeatures }
df = pd.DataFrame(feature_dict)
df.to_csv('features.csv', index=False)

print("Finish successfully")






