import numpy as np
import matplotlib.pyplot as plt

RSA_COMPUTE = "rsa_copmute_root_times_microseconds.txt"
RSA_DECRYPT = "rsa_decrypt_times_microseconds.txt"
TIME = "randsc_pmul_times.txt"
MSB = "randsc_pmul_msb.txt"
MS = "randsc_pmul_ms.txt"


## Takes files as an input and converts to array
def convert_file_to_array(file):
    output = []
    file = open(file, "r")
    for row in file:
        output.append(int(row))

    return output


def convert_ns_to_ms(filename, output):
    out = open(output, "w")
    with open(filename) as file:
        for row in file:
            if int(row) > 300000:
                row = int(row) // 10000
            out.write(str(int(row)//100) + "\n")

    out.close()


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
    print(maximal)
    heat = [[0 for x in range(maximal)] for y in range(maximal)]
    for x in range(10000):
        print(p[x])
        heat[p[x]][q[x]] += 1
    return heat


## Draws heatmap
def draw_heatmap():
    data = fill_heat2(MS, MSB)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([1250, 1500])
    plt.xlim([0, 270])
    plt.ylabel("Time in nanoseconds/100")
    plt.xlabel("MSB")
    f.show()
    f.savefig('heatmap-msb-vs-time-ecc.png')


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
    plt.savefig("rsa_decrypt_times_nanoseconds.png")
    plt.show()




if __name__ == '__main__':
    #numpy_hist_txt()
    draw_heatmap()
