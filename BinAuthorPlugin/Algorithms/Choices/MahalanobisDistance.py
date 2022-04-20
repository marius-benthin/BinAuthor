from numpy import array, mean, dot, sqrt, linalg, tile

from ida_nalt import get_root_filename

'''
This code was translated from: https://people.revoledu.com/kardi/tutorial/Similarity/MahalanobisDistance.html
It was tested using the sample dataset on this blogsite.
'''


class Mahalanobis:

    def __init__(self):
        self.fileName: str = get_root_filename()
        self.authorName = self.fileName

    def mahalanobisDistance(self, A, B):
        A = array(A)
        B = array(B)

        AShape = A.shape
        BShape = B.shape

        n = AShape[0] + BShape[0]

        if AShape[1] != BShape[1]:
            print("Number of columns of A and B must be the same!")
            return
        else:
            xDiff = mean(A, axis=0) - mean(B, axis=0)
            cA = self.Covariance(A)
            cB = self.Covariance(B)
            pC = dot(AShape[0] / float(n), cA) + dot(BShape[0] / float(n), cB)
            return sqrt(dot(dot(xDiff, linalg.inv(pC)), xDiff))

    @staticmethod
    def Covariance(X):
        xShape = X.shape
        Xc = X - tile(mean(X, axis=0), (xShape[0], 1))
        return dot(Xc.T, Xc) / xShape[0]

    # def getMD(self):


''' Example Usage:        
test = Mahalanobis()

vector1 = [[2, 2],[2, 5],[6, 5],[7, 3],[4, 7],[6, 4],[5, 3],[4, 6],[2, 5],[1, 3]]
vector2 = [[6, 5], [7, 4], [8, 7], [5, 6], [5, 4]]

print(test.mahalanobisDistance(vector1,vector2))

'''
