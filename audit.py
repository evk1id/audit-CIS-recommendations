"""
	YAML-file from project Wazuh:
	https://github.com/wazuh/wazuh/tree/main/ruleset/sca
"""

# Library
import csv
import sys
import yaml
import subprocess
import os
import re


# Read yaml-file
def read_yaml(filename):
    """
		Данная функция читает yaml-файл, возвращая Python-объект
		
	:param filename: путь к yaml-файлу для чтения
	:return: список, содержащий данные из yaml-файла
	"""
	with open(filename, 'r') as file:
		return yaml.safe_load(file)


# Get 'checks' from data
def read_rules(data):
    """
		Извлекает список правил из структуры данных.
	
	:param data: словарь, полученный из yaml-файла
	:return: список всех найденных правил
	"""
	rules = []
	for check in data['checks']:
		if 'rules' in check:
			rules.extend(check['rules'])
	return rules


# Parse rule
def parse_rule(rule):
    """
		Парсит строку с правилом и возвращает структурированный словарь
		
	:param rule: список правил
	:return: словарь с разобранным правилом, который содержит:
		- original: оригинальная строка правила
		- negate: флаг отрицания (True/False)
		- type: тип операции ('command', 'file', 'directory')
		- conditions: условия проверки
		
	Формат правила:
		[not ]<type>:<value> -> conditions
	"""
	result = {'original': rule}

	# Processing 'not'
	if rule.startswith('not '):
		result['negate'] = True
		rule = rule[4:].strip()
	else:
		result['negate'] = False

	# Split data, e.g.: "c:findmnt --kernel /tmp -> r:nodev"  ->  "c:findmnt --kernel /tmp" && "r:nodev"
	parts = [part.strip() for part in rule.split('->')]

	# Operation type: 'command', 'file', 'directory'
	if parts[0].startswith('c:'):
		result['type'] = 'command'
		result['command'] = parts[0][2:].strip()
	elif parts[0].startswith('f:'):
		result['type'] = 'file'
		result['file'] = parts[0][2:].strip()
	elif parts[0].startswith('d:'):
		result['type'] = 'directory'
		result['directory'] = parts[0][2:].strip()

	result['conditions'] = []
	for part in parts[1:]:
		if '&&' in part:
			conditions = [c.strip() for c in part.split('&&')]  # Several conditions that are described using '&&'

			for cond in conditions:
				if cond.startswith('r:'):  # 'r:' == regex
					result['conditions'].append({'type': 'regex', 'pattern': cond[2:]})
				elif cond.startswith('!r:'):  # '!r:' == not regex
					result['conditions'].append({'type': 'regex', 'pattern': cond[3:]})
				elif cond.startswith('n:'):  # 'n:' == compare
					pattern, operator, value = compare_rule(cond[2:])
					result['conditions'].append({'type': 'compare', 'pattern': pattern, 'operator': operator, 'value': value})

		else:  # Only 1 condition
			if part.startswith('r:'):  # 'r:' == regex
				result['conditions'].append({'type': 'regex', 'pattern': part[2:]})
			elif part.startswith('!r:'):  # '!r:' == not regex
				result['conditions'].append({'type': 'regex', 'pattern': part[3:]})
			elif part.startswith('n:'):  # 'n:' == compare
				pattern, operator, value = compare_rule(part[2:])
				result['conditions'].append({'type': 'compare', 'pattern': pattern, 'operator': operator, 'value': value})

	return result


def compare_rule(part):
    """
		Парсит строку с условием сравнения и возвращает его компоненты
		
	:param part: получает строку следующего вида:
		"<pattern> compare <operator> <value>"
	:return: возвращает 3 элемента:
		- pattern: параметр сравнения
		- operator: оператор сравнения
		- value: значение для сравнения
	"""
	parts = part.split('compare')  # Split data, e.g.: "<pattern> compare <operator> <value>"  ->  "<pattern>" && "<operator> <value>"
	pattern = parts[0]
	operator_pattern = r'(<=|>=|==|=|!=|<|>)'
	op_match = re.match(operator_pattern, parts[1][1:])  # Searching
	if not op_match:
		return None, None, None
	operator = op_match.group(1)
	if operator == ('<' or '>' or '='):
		value = parts[1][2:].strip()
	else:
		value = parts[1][3:].strip()
	return pattern, operator, value


# Command
def check_command_rule(rule):

	check = [{
		'title': 'value',
		'original': rule.get('original'),
		'details': [],
		'passed': 'value',
		'output': 'value',
		'error': 'value'
	}]
	command = rule.get('command')

	try:
		r = subprocess.run(command, shell=True, text=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)  # timeout=120 -> dont wait too long during debugging
		output = r.stdout
		if r.stderr:
			output += f"\nError: {r.stderr}"

		output = output.lower()

		all_conditions_passed = True
		conditions = rule.get('conditions')
		for condition in conditions:
			tmp = condition.get('pattern').lower()
			if condition['type'] == 'regex':
				passed = bool(re.search(tmp, output, re.IGNORECASE | re.MULTILINE))  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
				check[0]['details'].append({
					'type': 'regex',
					'pattern': condition['pattern'],
					'passed': passed
				})
				all_conditions_passed = all_conditions_passed and passed
			elif condition['type'] == 'neg_regex':
				passed = not bool(re.search(tmp, output , re.IGNORECASE | re.MULTILINE))  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
				check[0]['details'].append({
					'type': 'neg_regex',
					'pattern': condition['pattern'],
					'passed': passed
				})
				all_conditions_passed = all_conditions_passed and passed

			elif condition['type'] == 'compare':
				match = re.search(tmp, output, re.IGNORECASE | re.MULTILINE)  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
				if match:
					current_value = int(match.group(1))
					if condition['operator'] == '==' or condition['operator'] == '=':
						passed = current_value == int(condition['value'])
					elif condition['operator'] == '!=':
						passed = current_value != int(condition['value'])
					elif condition['operator'] == '>':
						passed = current_value > int(condition['value'])
					elif condition['operator'] == '>=':
						passed = current_value >= int(condition['value'])
					elif condition['operator'] == '<':
						passed = current_value < int(condition['value'])
					elif condition['operator'] == '<=':
						passed = current_value <= int(condition['value'])
					check[0]['details'].append({
						'type': 'compare',
						'pattern': condition['pattern'],
						'value': condition['value'],
						'passed': passed
					})
					all_conditions_passed = all_conditions_passed and passed

		if rule['negate']:
			all_conditions_passed = not all_conditions_passed

		check[0]['passed'] = all_conditions_passed
		check[0]['output'] = output
		return check

	except subprocess.TimeoutExpired as e:
		check[0]['error'] = str(e)
		check[0]['passed'] = 'Error'
		return check

	except Exception as e:
		check[0]['error'] = str(e)
		check[0]['passed'] = 'Error'
		return check


# File
def check_file_rule(rule):
	file_path = rule.get('file')
	if not os.path.exists(file_path):
		return {
			'title': 'value',
			'original': rule.get('original'),
			'passed': False,
			'error': f'File {file_path} does not exist'
		}
	check = [{
		'title': 'value',
		'original': rule.get('original'),
		'details': [],
		'passed': 'value',
		'error': 'value'
	}]
	try:
		with open(file_path, 'r') as f:
			content = f.read()

		content = content.lower()

		all_conditions_passed = True
		conditions = rule.get('conditions')
		for condition in conditions:
			tmp = condition.get('pattern').lower()
			if condition['type'] == 'regex':
				passed = bool(re.search(tmp, content, re.IGNORECASE | re.MULTILINE))  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
				check[0]['details'].append({
					'type': 'regex',
					'pattern': condition['pattern'],
					'passed': passed
				})
				all_conditions_passed = all_conditions_passed and passed
			elif condition['type'] == 'neg_regex':
				passed = not bool(re.search(tmp, content, re.IGNORECASE | re.MULTILINE))  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
				check[0]['details'].append({
					'type': 'neg_regex',
					'pattern': condition['pattern'],
					'passed': passed
				})
				all_conditions_passed = all_conditions_passed and passed

			elif condition['type'] == 'compare':
				pattern = condition['pattern'].lower()
				pattern = pattern.strip()
				match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)  # or re.match() ?? re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
				if match:
					current_value = int(match.group(1))
					if condition['operator'] == '==' or condition['operator'] == '=':
						passed = current_value == int(condition['value'])
					elif condition['operator'] == '!=':
						passed = current_value != int(condition['value'])
					elif condition['operator'] == '>':
						passed = current_value > int(condition['value'])
					elif condition['operator'] == '>=':
						passed = current_value >= int(condition['value'])
					elif condition['operator'] == '<':
						passed = current_value < int(condition['value'])
					elif condition['operator'] == '<=':
						passed = current_value <= int(condition['value'])
					check[0]['details'].append({
						'type': 'compare',
						'pattern': condition['pattern'],
						'value': condition['value'],
						'passed': passed
					})
					all_conditions_passed = all_conditions_passed and passed

		if rule['negate']:
			all_conditions_passed = not all_conditions_passed
		check[0]['passed'] = all_conditions_passed
		return check

	except Exception as e:
		check[0]['error'] = str(e)
		check[0]['passed'] = 'Error'
		return check


def check_directory_rule(rule):
	path = rule.get('directory')
	check = [{
		'title': 'value',
		'original': rule.get('original'),
		'details': [],
		'passed': 'value',
		'error': 'value'
	}]

	try:
		files = [f for f in os.listdir(path) if re.search('.*', f)]

		all_conditions_passed = True
		for file in files:
			file_path = os.path.join(path, file)
			if not os.path.isfile(file_path):
				continue

			with open(file_path, 'r') as f:
				content = f.read()

			content = content.lower()

			conditions = rule.get('conditions')
			for condition in conditions:
				tmp = condition.get('pattern').lower()
				if condition['type'] == 'regex':
					passed = bool(re.search(tmp, content, re.IGNORECASE | re.MULTILINE))  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
					check[0]['details'].append({
						'type': 'regex',
						'pattern': condition['pattern'],
						'passed': passed
					})
					all_conditions_passed = all_conditions_passed and passed
				elif condition['type'] == 'neg_regex':
					passed = not bool(re.search(tmp, content, re.IGNORECASE | re.MULTILINE))  # re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
					check[0]['details'].append({
						'type': 'neg_regex',
						'pattern': condition['pattern'],
						'passed': passed
					})
					all_conditions_passed = all_conditions_passed and passed

				elif condition['type'] == 'compare':
					pattern = condition['pattern'].lower()
					pattern = pattern.strip()
					match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)  # or re.match() ?? re.IGNORECASE e.g. PermitRootLogin == permitrootlogin
					if match:
						current_value = int(match.group(1))
						if condition['operator'] == '==' or condition['operator'] == '=':
							passed = current_value == int(condition['value'])
						elif condition['operator'] == '!=':
							passed = current_value != int(condition['value'])
						elif condition['operator'] == '>':
							passed = current_value > int(condition['value'])
						elif condition['operator'] == '>=':
							passed = current_value >= int(condition['value'])
						elif condition['operator'] == '<':
							passed = current_value < int(condition['value'])
						elif condition['operator'] == '<=':
							passed = current_value <= int(condition['value'])
						check[0]['details'].append({
							'type': 'compare',
							'pattern': condition['pattern'],
							'value': condition['value'],
							'passed': passed
						})
						all_conditions_passed = all_conditions_passed and passed

		if rule['negate']:
			all_conditions_passed = not all_conditions_passed
		check[0]['passed'] = all_conditions_passed
		return check

	except Exception as e:
		check[0]['error'] = str(e)
		check[0]['passed'] = 'Error'
		return check


if __name__ == '__main__':

	try:
		filename = sys.argv[1]
	except IndexError:
		exit("USAGE: python3 parser-wazuh.py filename")
	data = read_yaml(filename)
	data = read_rules(data)

	parsed_data = []
	for d in data:
		parsed_data.append(parse_rule(d))

	checked_data = []
	iter = 1
	for d in parsed_data:
		iter += 1
		if iter == 246:
			print(iter)
		if d['type'] == 'command':
			checked_data.append(check_command_rule(d))
			print(d['original'])
		elif d['type'] == 'file':
			checked_data.append(check_file_rule(d))
			print(d['original'])
		elif d['type'] == 'directory':
			checked_data.append(check_directory_rule(d))
			print(d['original'])

	# Output CSV-file
	with open('output.csv', 'w', newline='') as f:
		writer = csv.writer(f)
		writer.writerow(['original', 'passed'])

		for d in checked_data:
			if isinstance(d, list) and len(d) > 0 and isinstance(d[0], dict):
				writer.writerow([d[0]['original'], d[0]['passed']])
			elif isinstance(d, dict):
				writer.writerow([d['original'], d['passed']])