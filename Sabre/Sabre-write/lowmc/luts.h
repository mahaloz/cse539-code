#include <cassert>
#include <iomanip>
#include <iostream>
#include<tuple>
#include <set>
#include <vector>

constexpr size_t NROWS = 128;
constexpr size_t NCOLS = 32;

std::vector<std::tuple<int, int, int>> lut_recipe_[NCOLS];
for(size_t j = 0 ; j < NCOLS; ++j)
{
	lut_recipe_[j].resize(22);
}