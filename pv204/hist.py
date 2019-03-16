import numpy as np
import matplotlib.pyplot as plt


def numpy_hist_txt():
    f1 = np.loadtxt('rsa-p-msb-10000.txt', unpack='False')
    #f2 = np.loadtxt('rsa-q-msb-10000.txt', unpack='False')

    plt.hist(f1, histtype='bar',color="orange", bins=500, label="MSB P")
    plt.xlabel('MSB P')
    plt.title('MSB P - 10000 sample')
    plt.legend()
    plt.savefig("sample-p-q-msb-10000-2.png")
    plt.show()
