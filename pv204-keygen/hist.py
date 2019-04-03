import numpy as np
import matplotlib.pyplot as plt

# UNBLINDED - RICHARDS
COMPUTE_ROOT_RR = "measureComputeRootRR.txt"  # 1. half HW data and random exponent
COMPUTE_ROOT_LR = "measureComputeRootLR.txt"  # 2. data consisting of zeroes and random exponent
COMPUTE_ROOT_HR = "measureComputeRootHR.txt"  # 3. data consisting of ones and random exponent
COMPUTE_ROOT_RL = "measureComputeRootRL.txt"  # 4. with half HW data and low HW exponent
COMPUTE_ROOT_RH = "measureComputeRootRH.txt"  # 5. with half HW data and high HW exponent

DECRYPT_RR = "measureDecryptRR.txt"  # 1. half HW data and random exponent
DECRYPT_LR = "measureDecryptLR.txt"  # 2. data consisting of zeroes and random exponent
DECRYPT_HR = "measureDecryptHR.txt"  # 3. data consisting of ones and random exponent
DECRYPT_RL = "measureDecryptRL.txt"  # 4. with half HW data and low HW exponent
DECRYPT_RH = "measureDecryptRH.txt"  # 5. with half HW data and high HW exponent

DIGEST_RR = "measureSignDigestRR.txt"  # 1. half HW data and random exponent
DIGEST_LR = "measureSignDigestLR.txt"  # 2. data consisting of zeroes and random exponent
DIGEST_HR = "measureSignDigestHR.txt"  # 3. data consisting of ones and random exponent
DIGEST_RL = "measureSignDigestRL.txt"  # 4. with half HW data and low HW exponent
DIGEST_RH = "measureSignDigestRH.txt"  # 5. with half HW data and high HW exponent

SIGN_RR = "measureSignRR.txt"  # 1. half HW data and random exponent
SIGN_LR = "measureSignLR.txt"  # 2. data consisting of zeroes and random exponent
SIGN_HR = "measureSignHR.txt"  # 3. data consisting of ones and random exponent
SIGN_RL = "measureSignRL.txt"  # 4. with half HW data and low HW exponent
SIGN_RH = "measureSignRH.txt"  # 5. with half HW data and high HW exponent

TO_SEXP_RR = "measureToSexpRR.txt"  # 1. half HW data and random exponent
TO_SEXP_LR = "measureToSexpLR.txt"  # 2. data consisting of zeroes and random exponent
TO_SEXP_HR = "measureToSexpHR.txt"  # 3. data consisting of ones and random exponent
TO_SEXP_RL = "measureToSexpRL.txt"  # 4. with half HW data and low HW exponent
TO_SEXP_RH = "measureToSexpRH.txt"  # 5. with half HW data and high HW exponent

# BLINDED - FILIP
RSA_COMPUTE = "rsa_copmute_root_times_nanoseconds_100k.txt"
RSA_DECRYPT = "rsa_decrypt_tr_times_nanoseconds_100k.txt"
RSA_KEYPAIR_FROM_SEXP = "rsa_keypair_from_sexp_times_nanoseconds_100k.txt"
RSA_SIGN = "rsa_sign_tr_times_nanoseconds_100k.txt"
RSA_SIGN_DIGEST = "rsa_sha256_sign_digest_tr_times_nanoseconds_100k.txt"

SIGN_MS = "rsa_sha256_sign_ms.txt"
DIGEST_MS = "rsa_sha256_digest_ms.txt"
COMPUTE_MS = "rsa_compute_tr_times_ms_100k.txt"


## Takes files as an input and converts to array
def convert_file_to_array(file):
    output = []
    file = open(file, "r")
    for row in file:
        output.append(int(row))

    return output


def convert_ns_to_ms(filename, output):
    out = open(output, "w")
    counter = 0
    with open(filename) as file:
        for row in file:
            out.write(str(int(row)//1000) + "\n")
            counter += 1
            if counter == 100000:
                break

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
    heat = [[0 for x in range(maximal)] for y in range(maximal)]
    for x in range(10000):
        heat[p[x]][q[x]] += 1
    return heat


## Draws heatmap
def draw_heatmap():
    data = fill_heat2(COMPUTE_MS, SIGN_MS)
    f = plt.figure(1)
    plt.imshow(data, cmap='hot', interpolation='nearest')
    plt.gca().invert_yaxis()
    plt.ylim([1750, 2300])
    plt.xlim([1650, 2200])
    plt.ylabel("SIGN_tr microseconds")
    plt.xlabel("COMPUTE_ROOT microseconds")
    f.show()
    f.savefig('heatmap-root-vs-sign-blinded.png')


def numpy_hist_txt():
    f1 = np.loadtxt(TO_SEXP_RR, unpack='False')
    f2 = np.loadtxt(TO_SEXP_LR, unpack='False')
    f3 = np.loadtxt(TO_SEXP_HR, unpack='False')
    f4 = np.loadtxt(TO_SEXP_RL, unpack='False')
    f5 = np.loadtxt(TO_SEXP_RH, unpack='False')

    plt.hist(f5, histtype='bar', color="orange", bins=500, label="KEYPAIR FROM SEXP", range=(1800, 5000))
    plt.xlabel('TIME in nanoseconds')
    plt.title('rsa_keypair_from_sexp_tr() TIME - 100 000 samples')
    plt.legend()
    plt.savefig("rsa_keypair_from_sexp_tr_times_nanoseconds.png")
    plt.show()


# Draws histograms
def compute_root_txt():
    f1 = np.loadtxt(COMPUTE_ROOT_RR, unpack='False')
    f2 = np.loadtxt(COMPUTE_ROOT_LR, unpack='False')
    f3 = np.loadtxt(COMPUTE_ROOT_HR, unpack='False')
    f4 = np.loadtxt(COMPUTE_ROOT_RL, unpack='False')
    f5 = np.loadtxt(COMPUTE_ROOT_RH, unpack='False')

    #plt.hist(f1, histtype='bar',color="orange", bins=500, label="random exponent", range=(900000, 1600000))
    #plt.hist(f2, histtype='bar', color="red", bins=500, label="zeroes and random exponent", range=(900000, 1600000))
    #plt.hist(f3, histtype='bar', color="blue", bins=500, label="ones and random exponent", range=(900000, 1600000))
    plt.hist(f4, histtype='bar', color="orange", bins=500, label="low HW exponent", range=(40000, 1500000))
    plt.hist(f5, histtype='bar', color="green", bins=500, label="high HW exponent", range=(40000, 1500000))
    plt.xlabel('TIME in nanoseconds')
    plt.title('COMPUTE ROOT TIME - 1M samples')
    plt.legend()
    plt.savefig("rsa_compute_root_lhw_hhw_exponent_nanoseconds.png")
    plt.show()


def decrypt_txt():
    f1 = np.loadtxt(DECRYPT_RR, unpack='False')
    f2 = np.loadtxt(DECRYPT_LR, unpack='False')
    f3 = np.loadtxt(DECRYPT_HR, unpack='False')
    f4 = np.loadtxt(DECRYPT_RL, unpack='False')
    f5 = np.loadtxt(DECRYPT_RH, unpack='False')

    #plt.hist(f1, histtype='bar', color="orange", bins=500, label="random exponent", range=(900000, 1600000))
    #plt.hist(f2, histtype='bar', color="red", bins=500, label="zeroes and random exponent", range=(900000, 1600000))
    #plt.hist(f3, histtype='bar', color="blue", bins=500, label="ones and random exponent", range=(900000, 1600000))
    plt.hist(f4, histtype='bar', color="orange", bins=500, label="low HW exponent", range=(40000, 1500000))
    plt.hist(f5, histtype='bar', color="green", bins=500, label="high HW exponent", range=(40000, 1500000))
    plt.xlabel('TIME in nanoseconds')
    plt.title('COMPUTE DECRYPT TIME - 1M samples')
    plt.legend()
    #plt.savefig("rsa_decrypt_rand_exponent_nanoseconds.png")
    plt.savefig("rsa_decrypt_lhw_hhw_exponent_nanoseconds.png")
    plt.show()


def digest_txt():
    f1 = np.loadtxt(DIGEST_RR, unpack='False')
    f2 = np.loadtxt(DIGEST_LR, unpack='False')
    f3 = np.loadtxt(DIGEST_HR, unpack='False')
    f4 = np.loadtxt(DIGEST_RL, unpack='False')
    f5 = np.loadtxt(DIGEST_RH, unpack='False')

    #plt.hist(f1, histtype='bar', color="orange", bins=500, label="random exponent", range=(900000, 1600000))
    #plt.hist(f2, histtype='bar', color="red", bins=500, label="zeroes and random exponent", range=(900000, 1600000))
    #plt.hist(f3, histtype='bar', color="blue", bins=500, label="ones and random exponent", range=(900000, 1600000))
    plt.hist(f4, histtype='bar', color="orange", bins=500, label="low HW exponent", range=(40000, 1500000))
    plt.hist(f5, histtype='bar', color="green", bins=500, label="high HW exponent", range=(40000, 1500000))
    plt.xlabel('TIME in nanoseconds')
    plt.title('SIGN DIGEST TIME - 1M samples')
    plt.legend()
    #plt.savefig("rsa_digest_rand_exponent_nanoseconds.png")
    plt.savefig("rsa_digest_lhw_hhw_exponent_nanoseconds.png")
    plt.show()


def sign_txt():
    f1 = np.loadtxt(SIGN_RR, unpack='False')
    f2 = np.loadtxt(SIGN_LR, unpack='False')
    f3 = np.loadtxt(SIGN_HR, unpack='False')
    f4 = np.loadtxt(SIGN_RL, unpack='False')
    f5 = np.loadtxt(SIGN_RH, unpack='False')

    #plt.hist(f1, histtype='bar', color="orange", bins=500, label="random exponent", range=(900000, 1600000))
    #plt.hist(f2, histtype='bar', color="red", bins=500, label="zeroes and random exponent", range=(900000, 1600000))
    #plt.hist(f3, histtype='bar', color="blue", bins=500, label="ones and random exponent", range=(900000, 1600000))
    plt.hist(f4, histtype='bar', color="orange", bins=500, label="low HW exponent", range=(40000, 1500000))
    plt.hist(f5, histtype='bar', color="green", bins=500, label="high HW exponent", range=(40000, 1500000))
    plt.xlabel('TIME in nanoseconds')
    plt.title('SIGN TIME - 1M samples')
    plt.legend()
    #plt.savefig("rsa_sign_rand_exponent_nanoseconds.png")
    plt.savefig("rsa_sign_lhw_hhw_exponent_nanoseconds.png")
    plt.show()


def to_sexp_txt():
    f1 = np.loadtxt(TO_SEXP_RR, unpack='False')
    f2 = np.loadtxt(TO_SEXP_LR, unpack='False')
    f3 = np.loadtxt(TO_SEXP_HR, unpack='False')
    f4 = np.loadtxt(TO_SEXP_RL, unpack='False')
    f5 = np.loadtxt(TO_SEXP_RH, unpack='False')

    #plt.hist(f1, histtype='bar', color="orange", bins=500, label="random exponent", range=(2300, 5000))
    #plt.hist(f2, histtype='bar', color="red", bins=500, label="zeroes and random exponent", range=(2300, 5000))
    #plt.hist(f3, histtype='bar', color="blue", bins=500, label="ones and random exponent", range=(2300, 5000))
    plt.hist(f4, histtype='bar', color="orange", bins=500, label="low HW exponent", range=(1900, 4500))
    plt.hist(f5, histtype='bar', color="green", bins=500, label="high HW exponent", range=(1900, 4500))
    plt.xlabel('TIME in nanoseconds')
    plt.title('TO SEXP TIME - 1M samples')
    plt.legend()
    #plt.savefig("rsa_to_sexp_rand_exponent_nanoseconds.png")
    plt.savefig("rsa_to_sexp_lhw_hhw_exponent_nanoseconds.png")
    plt.show()


if __name__ == '__main__':
    to_sexp_txt()
