import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('--in_file', default='zizi.list')
	parser.add_argument('--out_file', default='FAKE_KDD.txt')

	args = parser.parse_args()

	f = open(args.in_file, 'r')
	content = f.readlines()
	f.close()
	content = [line.replace('\n', '') for line in content]

	result = []

	for i, line1 in enumerate(content):
		line1 = line1.split(' ')
		num_conn1 = line1[0]
		start_time1 = line1[1]
		orig_p1 = line1[2]
		resp_p1 = line1[3]
		orig_h1 = line1[4]
		resp_h1 = line1[5]
		duration1 = line1[6]
		protocol1 = line1[7]
		service1 = line1[8]
		flag1 = line1[9]
		src_bytes1 = line1[10]
		dst_bytes1 = line1[11]
		land1 = line1[12]
		wrong_fragment1 = line1[13]
		urg1 = line1[14]
		hot1 = line1[15]
		num_failed_logins1 = line1[16]
		logged_in1 = line1[17]
		num_compromised1 = line1[18]
		root_shell1 = line1[19]
		su_attempted1 = line1[20]
		num_root1 = line1[21]
		num_file_creations1 = line1[22]
		num_shells1 = line1[23]
		num_access_files1 = line1[24]
		num_outbound_cmds1 = line1[25]
		is_hot_login = line1[26]
		is_guest_login = line1[27]


		start_time_11, start_time_12 = start_time1.split('.')
		start_time_11 = int(start_time_11)
		start_time_12 = int(start_time_12)

		count = 0
		serror = 0
		rerror = 0
		same_srv = 0
		diff_srv = 0
		srv_count = 0
		srv_serror = 0
		srv_rerror = 0
		srv_diff_host = 0
		serror_rate = 0
		rerror_rate = 0
		same_srv_rate = 0
		diff_srv_rate = 0
		srv_serror_rate = 0
		srv_rerror_rate = 0
		srv_diff_host_rate = 0

		for j in range(i):
			line2 = content[j]
			line2 = line2.split(' ')
			num_conn2 = line2[0]
			start_time2 = line2[1]
			orig_p2 = line2[2]
			resp_p2 = line2[3]
			orig_h2 = line2[4]
			resp_h2 = line2[5]
			duration2 = line2[6]
			protocol2 = line2[7]
			service2 = line2[8]
			flag2 = line2[9]


			start_time_21, start_time_22 = start_time2.split('.')
			start_time_21 = int(start_time_21)
			start_time_22 = int(start_time_22)

			if start_time_11 - start_time_21 <= 2 and start_time_21 <= start_time_11:
				if resp_h1 == resp_h2:
					count += 1

					if flag2 == 'S0' or flag2 == 'S1' or flag2 == 'S2' or flag2 == 'S3':
						serror += 1

					if flag2 == 'REJ':
						rerror += 1

					if service2 != 'other' and service1 == service2:
						same_srv += 1

					if service1 != service2:
						diff_srv += 1

				if resp_p1 == resp_p2:
					srv_count += 1

					if flag2 == 'S0' or flag2 == 'S1' or flag2 == 'S2' or flag2 == 'S3':
						srv_serror += 1

					if flag2 == 'REJ':
						srv_rerror += 1

					if resp_h1 != resp_h2:
						srv_diff_host += 1

		if count != 0:
			serror_rate = serror / count
			rerror_rate = rerror / count
			same_srv_rate = same_srv / count
			diff_srv_rate = diff_srv / count

		if srv_count != 0:
			srv_serror_rate = srv_serror / srv_count
			srv_rerror_rate = srv_rerror / srv_count
			srv_diff_host_rate = srv_diff_host / srv_count

		if i <= 100:
			k = 0
		else:
			k = i - 100

		dst_host_count = 0
		dst_host_serror = 0
		dst_host_rerror = 0
		dst_host_same_srv = 0
		dst_host_diff_srv = 0
		dst_srv_host_count = 0
		dst_host_srv_serror = 0
		dst_host_srv_rerror = 0
		dst_host_srv_diff_host = 0
		dst_host_same_src_port = 0
		dst_host_serror_rate = 0
		dst_host_rerror_rate = 0
		dst_host_same_srv_rate = 0
		dst_host_diff_srv_rate = 0
		dst_host_srv_serror_rate = 0
		dst_host_srv_rerror_rate = 0
		dst_host_srv_diff_host_rate = 0
		dst_host_same_src_port_rate = 0

		for l in range(k, i):
			line3 = content[l]
			line3 = line3.split(' ')
			num_conn3 = line3[0]
			start_time3 = line3[1]
			orig_p3 = line3[2]
			resp_p3 = line3[3]
			orig_h3 = line3[4]
			resp_h3 = line3[5]
			duration3 = line3[6]
			protocol3 = line3[7]
			service3 = line3[8]
			flag3 = line3[9]

			if resp_h1 == resp_h3:
				dst_host_count += 1

				if flag3 == 'S0' or flag3 == 'S1' or flag3 == 'S2' or flag3 == 'S3':
					dst_host_serror += 1

				if flag3 == 'REJ':
					dst_host_rerror += 1

				if service3 == 'other' and service1 == service3:
					dst_host_same_srv += 1

				if service1 != service3:
					dst_host_diff_srv += 1

			if resp_p1 == resp_p3:
				dst_srv_host_count += 1

				if flag3 == 'S0' or flag3 == 'S1' or flag3 == 'S2' or flag3 == 'S3':
					dst_host_srv_serror += 1

				if flag3 == 'REJ':
					dst_host_srv_rerror += 1

				if resp_h1 != resp_h2:
					dst_host_srv_diff_host += 1

			if orig_p1 == orig_p3:
				dst_host_same_src_port += 1

		if dst_host_count != 0:
			dst_host_serror_rate = dst_host_serror / dst_host_count
			dst_host_rerror_rate = dst_host_rerror / dst_host_count
			dst_host_same_srv_rate = dst_host_same_srv / dst_host_count
			dst_host_diff_srv_rate = dst_host_diff_srv / dst_host_count

		if dst_srv_host_count != 0:
			dst_host_srv_serror_rate = dst_host_srv_serror / dst_srv_host_count
			dst_host_srv_rerror_rate = dst_host_srv_rerror / dst_srv_host_count
			dst_host_srv_diff_host_rate = dst_host_srv_diff_host / dst_srv_host_count

		if i - k != 0:
			dst_host_same_src_port_rate = dst_host_same_src_port / (i - k)


		out = "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n".format(
			duration1, protocol1, service1, flag1, src_bytes1, dst_bytes1, land1, wrong_fragment1, urg1, hot1, 
			num_failed_logins1, logged_in1, num_compromised1, root_shell1, su_attempted1, num_root1, num_file_creations1, num_shells1, num_access_files1, num_outbound_cmds1, 
			is_hot_login, is_guest_login, count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate,
			srv_diff_host_rate, dst_host_count, dst_srv_host_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate,
			dst_host_srv_rerror_rate)

		result.append(out)

	f = open(args.out_file, 'w')
	f.writelines(result)
	f.close()


	