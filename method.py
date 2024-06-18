from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

import warnings
import numpy as np
from sklearn.neighbors import NearestNeighbors
from sklearn.utils import check_array, check_random_state
from collections import Counter

class teiann(object):
    def __init__(self, ratio=0.5, imb_threshold=0.5, k=5, random_state=None, verbose=True):
        self.ratio = ratio
        self.imb_threshold = imb_threshold
        self.k = k
        self.random_state = random_state
        self.verbose = verbose
        self.clstats = {}
        self.num_new = 0
        self.index_new = []

    def fit(self, X, y):
              self.X = check_array(X)
        self.y = np.array(y).astype(np.int64)
        self.random_state_ = check_random_state(self.random_state)
        self.unique_classes_ = set(self.y)

        for element in self.unique_classes_:
            self.clstats[element] = 0

        for element in self.y:
            self.clstats[element] += 1

        v = list(self.clstats.values())
        k = list(self.clstats.keys())
        self.maj_class_ = k[v.index(max(v))]

        if self.verbose:
            print('Majority class is %s and total number of classes is %s' % (self.maj_class_, len(self.unique_classes_)))

    def transform(self, X, y):
    
        self.new_X, self.new_y = self.oversample()

    def fit_transform(self, X, y):

        self.fit(X, y)
        self.new_X, self.new_y = self.oversample()

        self.new_X = np.concatenate((self.new_X, self.X), axis=0)
        self.new_y = np.concatenate((self.new_y, self.y), axis=0)

        return self.new_X, self.new_y

    def generate_samples(self, x, knns, knnLabels, cl):
        new_data = []
        new_labels = []  
               
        diff = 0.15
          
        
        for ind, elem in enumerate(x):
            min_knns = [ele for index, ele in enumerate(knns[ind][1:-1]) if knnLabels[ind][index + 1] == cl]

            if not min_knns:
                continue

            for i in range(0, int(self.gi[ind])):
                randi = self.random_state_.random_integers(0, len(min_knns) - 1)
                l = self.random_state_.random_sample()

                # オーバーサンプリングする先の少数派クラスとの距離を計算
                distance_to_minority = np.linalg.norm(self.X[min_knns[randi]] - self.X[elem])
                print(distance_to_minority)
                
                # 距離がdiffより小さい場合かつ多数派クラスの場合にのみ合成データを生成
                if distance_to_minority < diff and cl == self.maj_class_:
                    l = self.random_state_.uniform(0, 0.5)  # 多数派クラスに対して0 < i < 0.5
                    si = self.X[elem] + (self.X[min_knns[randi]] - self.X[elem]) * l
                    new_data.append(si)
                    new_labels.append(self.y[elem])
                    self.num_new += 1
                elif distance_to_minority < diff:
                    si = self.X[elem] + (self.X[min_knns[randi]] - self.X[elem]) * l
                    new_data.append(si)
                    new_labels.append(self.y[elem])
                    self.num_new += 1

        return (np.asarray(new_data), np.asarray(new_labels))


    def oversample(self):
        try:
            self.unique_classes_ = self.unique_classes_
        except:
            raise RuntimeError("You need to fit() before applying transform(), or simply fit_transform()")

        int_X = np.zeros([1, self.X.shape[1]])
        int_y = np.zeros([1])
        
        for cl in self.unique_classes_:
            imb_degree = float(self.clstats[cl]) / self.clstats[self.maj_class_]
            if imb_degree > self.imb_threshold:
                if self.verbose:
                    print('Class %s is within imbalance threshold' % cl)
            else:
                self.G = (self.clstats[self.maj_class_] - self.clstats[cl]) * self.ratio
                self.nearest_neighbors_ = NearestNeighbors(n_neighbors=self.k + 1)
                self.nearest_neighbors_.fit(self.X)
                minx = [ind for ind, exam in enumerate(self.X) if self.y[ind] == cl]
                knn = self.nearest_neighbors_.kneighbors(self.X[minx], return_distance=False)
                knnLabels = self.y[knn.ravel()].reshape(knn.shape)
                tempdi = [Counter(i) for i in knnLabels]
                self.ri = np.array([(sum(i.values()) - i[cl]) / float(self.k) for i in tempdi])

                if np.sum(self.ri):
                    self.ri = self.ri / np.sum(self.ri)

                self.gi = np.rint(self.ri * self.G)

                inter_X, inter_y = self.generate_samples(minx, knn, knnLabels, cl)

                if len(inter_X):
                    int_X = np.concatenate((int_X, inter_X), axis=0)
                if len(inter_y):
                    int_y = np.concatenate((int_y, inter_y), axis=0)

        self.index_new = [i for i in range(0, self.num_new)]
        return int_X[1:-1], int_y[1:-1]
