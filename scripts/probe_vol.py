from neurotrace.volatility.wrapper import VolatilityWrapper, _find_vol_command

cmd = _find_vol_command()
print("vol_cmd=", cmd)
w = VolatilityWrapper()
print("available=", w._vol3_available)
print("symbols=", w.symbol_dir)
print("command=", w.vol_command)
