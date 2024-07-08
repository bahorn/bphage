import sys
import pulp


def contains(small, big):
    for i in range(len(big) - len(small) + 1):
        for j in range(len(small)):
            if big[i + j] != small[j]:
                break
        else:
            return i
    return False


def does_contain(small, big):
    return contains(small, big) is not False


def score(length, usage):
    # checking if we break even
    cost_to_use = length + usage * 2
    cost_without = length * usage
    return cost_without - cost_to_use


patterns = {}

f = open(sys.argv[1], 'rb').read()
for n in range(8, 21):
    patterns[n] = {}

    for i in range(0, len(f) - n):
        pattern = f[i:n + i]

        if pattern not in patterns[n]:
            patterns[n][pattern] = 0

        patterns[n][pattern] += 1

# find the subsets that breakeven on use.
worthwhile = []
for n in range(20, 7, -1):
    for pattern, count in patterns[n].items():
        if score(len(pattern), count) <= 0:
            continue
        if sum([does_contain(pattern, good) for good in worthwhile]) >= 1:
            continue
        worthwhile.append(pattern)

# want to find if there are any free prefixes we can use for the worthwhile.
# some potentially easy bytes to save if we get this working.

blob = [0]
for good in worthwhile:
    blob += good

print(len(blob))
is_contained = []
for byte in f:
    if not does_contain(is_contained + [byte], blob):
        if len(is_contained) < 7:
            blob += is_contained
            is_contained = [byte]
        else:
            is_contained = []
            if byte in blob:
                is_contained = [byte]
                continue
            blob += [byte]
    else:
        is_contained += [byte]

blob += is_contained

print(len(blob), bytes(blob))

# now we need to generate set covers.
# They have a starting point in the data, and the blob, and a len
# obvs this is not the most efficent code. but we only need to check something
# like 14 mil combos at most, which is cheap.
# i = starting point in blob
# j = count from blob
# b = starting point in data
setcovers = []
for i in range(0, len(blob)):
    for j in range(1, len(blob) + 1 - i):
        for b in range(0, len(f) + 1 - j):
            if list(f[b:b + j]) == blob[i:i + j]:
                setcovers.append(
                    (
                        (i, j, b),
                        pulp.LpVariable(
                            f'v_{i}_{j}_{b}',
                            lowBound=0,
                            upBound=1,
                            cat=pulp.LpInteger)
                    )
                )
            pass

constraints = {}


def in_range(start, count, v):
    return (v >= start) and (v < (start + count))


# now we need to go through and see which set covers cover each character
for i in range(0, len(f)):
    constraints[i] = []
    for (a, b, c), variable in setcovers:
        if in_range(c, b, i):
            constraints[i].append(variable)

print('found')
# print(constraints)

prob = pulp.LpProblem("compression_min", pulp.LpMinimize)
# our objective is to minimize the total number of covers selected
prob += pulp.lpSum([v for _, v in setcovers])

# implement our constraint that each member of the final data is only covered
# once
for i, constraint in constraints.items():
    if len(constraint) == 0:
        # raise Exception(f'cant cover byte {i}')
        continue
    prob += pulp.lpSum(constraint) == 1

prob.solve()
print(pulp.LpStatus[prob.status])
res = []
for variable in prob.variables():
    if variable.varValue == 1.0:
        a, b, c = map(int, str(variable).split('_')[1:])
        res.append((a, b, c))

res.sort(key=lambda x: x[2])
print(res)
out = []
for a, b, _ in res:
    out += blob[a:a+b]

print(bytes(out), bytes(out) == f, len(out))

# with an optimal solution for our current one, we can see if there are any
# bytes in blob that do not get used an delete them, and resolve.
