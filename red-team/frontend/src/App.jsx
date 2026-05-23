import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppLayout } from './components/AppLayout.jsx'
import Dashboard  from './routes/Dashboard.jsx'
import Missions   from './routes/Missions.jsx'
import Modules    from './routes/Modules.jsx'
import Mission    from './routes/Mission.jsx'
import Workspace  from './routes/Workspace.jsx'
import Shell      from './routes/Shell.jsx'
import Detections from './routes/Detections.jsx'
import Reports    from './routes/Reports.jsx'
import Settings      from './routes/Settings.jsx'
import MissionReport from './routes/MissionReport.jsx'
import AttackReport  from './routes/AttackReport.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/"                      element={<Dashboard />}     />
          <Route path="/missions"              element={<Missions />}      />
          <Route path="/modules"               element={<Modules />}       />
          <Route path="/mission/:moduleId"     element={<Mission />}       />
          <Route path="/workspace/:sid"        element={<Workspace />}     />
          <Route path="/shell"                 element={<Shell />}         />
          <Route path="/detections"            element={<Detections />}    />
          <Route path="/reports"               element={<Reports />}       />
          <Route path="/settings"              element={<Settings />}      />
          <Route path="/report/:sid"           element={<MissionReport />} />
          <Route path="/attack-report/:sid"    element={<AttackReport />}  />
          <Route path="*"                      element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
