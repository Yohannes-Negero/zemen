// Package ethcal implements the Ethiopian calendar (13 months), Orthodox
// Easter, an arithmetic Islamic calendar, and generation of the
// Ethiopia-specific temporal signals Zemen's Temporal Context Engine uses.
//
// All dates are "civil dates": a time.Time at UTC midnight representing a
// calendar day, with no time-of-day meaning.
package ethcal

import (
	"fmt"
	"math"
	"time"
)

const unixEpochJDN = 2440588 // Julian Day Number of 1970-01-01

// Civil builds a civil date.
func Civil(y, m, d int) time.Time { return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC) }

// DateOf truncates a time to its civil date in its own location.
func DateOf(t time.Time) time.Time { return Civil(t.Year(), int(t.Month()), t.Day()) }

func jdn(t time.Time) int { return int(floorDiv(t.Unix(), 86400)) + unixEpochJDN }

func fromJDN(j int) time.Time { return time.Unix(int64(j-unixEpochJDN)*86400, 0).UTC() }

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func mod(a, b int) int { return ((a % b) + b) % b }

const ethEpochOffset = 1723856 // Amete Mihret JDN offset (Beyene-Kudlek)

// EthiopianToCivil converts an Ethiopian date to a civil (Gregorian) date.
func EthiopianToCivil(y, m, d int) time.Time {
	return fromJDN(ethEpochOffset + 365 + 365*(y-1) + y/4 + 30*m + d - 31)
}

// CivilToEthiopian converts a civil (Gregorian) date to an Ethiopian date.
func CivilToEthiopian(t time.Time) (y, m, d int) {
	j := jdn(t)
	r := mod(j-ethEpochOffset, 1461)
	n := r%365 + 365*(r/1460)
	y = 4*int(floorDiv(int64(j-ethEpochOffset), 1461)) + r/365 - r/1460
	m = n/30 + 1
	d = n%30 + 1
	return
}

// MonthNames are the 13 Ethiopian month names.
var MonthNames = []string{"Meskerem", "Tikimt", "Hidar", "Tahsas", "Tir", "Yekatit", "Megabit", "Miazia", "Genbot", "Sene", "Hamle", "Nehase", "Pagume"}

// FormatEthiopian renders a civil date as e.g. "Meskerem 17, 2017 E.C.".
func FormatEthiopian(t time.Time) string {
	y, m, d := CivilToEthiopian(t)
	return fmt.Sprintf("%s %d, %d E.C.", MonthNames[m-1], d, y)
}

// DaysInEthiopianMonth returns 30, or 5/6 for Pagume.
func DaysInEthiopianMonth(y, m int) int {
	if m < 13 {
		return 30
	}
	if y%4 == 3 {
		return 6
	}
	return 5
}

// OrthodoxEaster returns the Gregorian civil date of Orthodox Easter
// (Ethiopian Fasika), valid for 1900-2099.
func OrthodoxEaster(year int) time.Time {
	a, b, c := year%4, year%7, year%19
	d := (19*c + 15) % 30
	e := (2*a + 4*b - d + 34) % 7
	month := (d + e + 114) / 31
	day := (d+e+114)%31 + 1
	return Civil(year, month, day).AddDate(0, 0, 13) // Julian -> Gregorian
}

// IslamicToCivil converts a (tabular, arithmetic) Hijri date to a civil
// date. Real observance depends on moon sighting and can differ by a day
// or two, which is why Islamic signals are marked Approximate.
func IslamicToCivil(y, m, d int) time.Time {
	j := d + int(math.Ceil(29.5*float64(m-1))) + (y-1)*354 + (3+11*y)/30 + 1948439
	return fromJDN(j)
}
