import numpy as np
import matplotlib.pyplot as plt

RSA_COMPUTE = "rsa_copmute_root_times_microseconds.txt"
RSA_DECRYPT = "rsa_decrypt_times_microseconds.txt"


## Takes files as an input and converts to array
def convert_file_to_array(file):
    output = []
    file = open(file, "r")
    for row in file:
        output.append(int(row))

    return output


## This function fills the heat in the range of the maximal value
def fill_heat2(first, second):
    p = convert_file_to_array(first)
    q = convert_file_to_array(second)
    p_max = max(p)
    q_max = max(q)

    if q_max >= p_max:
        maximal = q_max + 1
    else:
        maximal = p_max + 1

    heat = [[0 for x in range(maximal)] for y in range(maximal)]
    for x in range(maximal):
        heat[p[x]][q[x]] += 1

    return heat


## Draws heatmap
def draw_heatmap():
    data = fill_heat2(RSA_COMPUTE, RSA_DECRYPT)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([175, 300])
    plt.xlim([0, 400])
    plt.xlabel("Time")
    plt.ylabel("MSB P")
    f.show()
    #f.savefig('heatmap-msb-p-vs-time-all.png')


## Draws histograms
def numpy_hist_txt():
    f1 = np.loadtxt(RSA_COMPUTE, unpack='False')
    f2 = np.loadtxt(RSA_DECRYPT, unpack='False')

    #plt.subplot(2, 1, 1)
    plt.hist(f2, histtype='bar',color="orange", bins=500, label="DECRYPT")
    plt.xlabel('TIME in microseconds')
    plt.title('rsa_decrypt() TIME - 10 000 samples')
    plt.legend()
    #plt.subplot(2, 1, 2)
    #plt.hist(f2, histtype='bar', bins=500, label="DECRYPT")
    #plt.xlabel('TIME in microseconds')
    # plt.title('RSA DECRYPT TIME')
    #plt.legend()
    plt.savefig("rsa_decrypt_times_microseconds.png")
    plt.show()




if __name__ == '__main__':
    #numpy_hist_txt()
    draw_heatmap()
