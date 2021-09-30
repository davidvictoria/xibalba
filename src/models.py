import sqlite3
import pendulum

con = sqlite3.connect('db/db.db')
cur = con.cursor()

def save_results(domain_cert, serial_cert, info_cert, sslabs_result_cert):

	dt = pendulum.now()
	timestamp_eval_cert = dt.int_timestamp

	cur.execute('INSERT INTO certs (domain_cert, serial_cert, timestamp_eval_cert, info_cert, sslabs_result_cert) VALUES (?,?,?,?,?)', (domain_cert, serial_cert, timestamp_eval_cert, info_cert, sslabs_result_cert))

	con.commit()
	
	return True

def get_last_result(domain_cert):
	variables = [domain_cert]
	cur.execute('select * from certs WHERE domain_cert = ? order by timestamp_eval_cert desc LIMIT 1', variables)
	result = cur.fetchone()

	return result

def get_domains_list():
	cur.execute('select domain_cert, timestamp_eval_cert from certs group by domain_cert')
	result = cur.fetchall()

	return result